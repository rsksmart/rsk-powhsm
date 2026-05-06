/*
 * Minimal CMS EnvelopedData decryptor using only mbedTLS for crypto/base64.
 *
 * Assumptions:
 *   - Input ct is either raw BER/DER or base64-encoded BER/DER.
 *   - ContentInfo.contentType is id-envelopedData and content is [0] EXPLICIT.
 *   - EnvelopedData.recipientInfos has at least one KeyTransRecipientInfo.
 *   - We use the first recipient only.
 *   - keyEncryptionAlgorithm is RSAES-OAEP with SHA-256.
 *   - contentEncryptionAlgorithm is AES-256-CBC with IV in parameters as OCTET STRING.
 *   - encryptedContent may be primitive [0] IMPLICIT OCTET STRING or constructed [0]
 *     containing OCTET STRING chunks.
 *   - Private key is PEM or DER.
 *
 * This is intentionally not a general CMS parser.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/rsa.h"

#define ERR_ASN1          -0x7000
#define ERR_FORMAT        -0x7001
#define ERR_PADDING       -0x7002
#define ERR_ALLOC         -0x7003

typedef struct {
    const uint8_t *wrapped_cek;
    size_t wrapped_cek_len;

    const uint8_t *iv;
    size_t iv_len;

    const uint8_t *enc;
    size_t enc_len;

    uint8_t *enc_alloc; /* non-NULL if constructed encryptedContent was flattened */
} cms_parts_t;

typedef struct {
    const uint8_t *p;
    size_t len;
    int indefinite;
} asn1_view_t;

static void secure_free(void *p, size_t n) {
    if (p != NULL) {
        mbedtls_platform_zeroize(p, n);
        free(p);
    }
}

static int asn1_get_len2(const uint8_t **p, const uint8_t *end,
                         size_t *len, int *indefinite) {
    size_t i, n;
    uint8_t c;

    if (*p >= end) return ERR_ASN1;

    c = *(*p)++;
    *indefinite = 0;

    if ((c & 0x80) == 0) {
        *len = c;
        return 0;
    }

    n = c & 0x7F;

    if (n == 0) {
        /* BER indefinite length */
        *len = 0;
        *indefinite = 1;
        return 0;
    }

    if (n > sizeof(size_t) || (size_t)(end - *p) < n) {
        return ERR_ASN1;
    }

    *len = 0;
    for (i = 0; i < n; i++) {
        *len = (*len << 8) | *(*p)++;
    }

    return 0;
}

/* Reads tag+length and returns a view of the value.
 * For definite length: advances *p past the whole TLV.
 * For indefinite length: leaves *p at the start of the value, caller must
 * locate the matching EOC and then advance manually.
 */
static int asn1_get_tlv2(const uint8_t **p, const uint8_t *end,
                         int expected_tag, asn1_view_t *out) {
    int tag;
    int ret;

    if (*p >= end) return ERR_ASN1;

    tag = *(*p)++;
    if (tag != expected_tag) return ERR_ASN1;

    ret = asn1_get_len2(p, end, &out->len, &out->indefinite);
    if (ret != 0) return ret;

    out->p = *p;

    if (!out->indefinite) {
        if ((size_t)(end - *p) < out->len) return ERR_ASN1;
        *p += out->len;
    }

    return 0;
}

/* Skip any TLV, including BER indefinite-length constructed forms. */
static int asn1_skip_any2(const uint8_t **p, const uint8_t *end) {
    int ret;
    size_t len;
    int indefinite;
    const uint8_t *q;

    if (*p >= end) return ERR_ASN1;

    /* consume tag */
    (*p)++;

    ret = asn1_get_len2(p, end, &len, &indefinite);
    if (ret != 0) return ret;

    if (!indefinite) {
        if ((size_t)(end - *p) < len) return ERR_ASN1;
        *p += len;
        return 0;
    }

    q = *p;
    for (;;) {
        if ((size_t)(end - q) < 2) return ERR_ASN1;
        if (q[0] == 0x00 && q[1] == 0x00) {
            q += 2;
            *p = q;
            return 0;
        }
        ret = asn1_skip_any2(&q, end);
        if (ret != 0) return ret;
    }
}

/* Enter a constructed value and compute its effective end.
 * For definite length: child_end = v->p + v->len
 * For indefinite length: scans until the matching EOC and returns that as child_end.
 * Caller should later advance parent pointer to after the EOC with asn1_finish_constructed().
 */
static int asn1_enter_constructed(const asn1_view_t *v, const uint8_t *global_end,
                                  const uint8_t **child_p, const uint8_t **child_end) {
    int ret;
    const uint8_t *q;

    *child_p = v->p;

    if (!v->indefinite) {
        *child_end = v->p + v->len;
        if (*child_end > global_end) return ERR_ASN1;
        return 0;
    }

    q = v->p;
    for (;;) {
        if ((size_t)(global_end - q) < 2) return ERR_ASN1;
        if (q[0] == 0x00 && q[1] == 0x00) {
            *child_end = q;
            return 0;
        }
        ret = asn1_skip_any2(&q, global_end);
        if (ret != 0) return ret;
    }
}

static int asn1_finish_constructed(const asn1_view_t *v, const uint8_t *child_end,
                                   const uint8_t *global_end, const uint8_t **parent_p) {
    if (!v->indefinite) {
        *parent_p = child_end;
        return 0;
    }

    if ((size_t)(global_end - child_end) < 2) return ERR_ASN1;
    if (child_end[0] != 0x00 || child_end[1] != 0x00) return ERR_ASN1;
    *parent_p = child_end + 2;
    return 0;
}

static int pkcs7_unpad(uint8_t *buf, size_t *len_io, size_t block_size) {
    size_t len, pad, i;

    if (buf == NULL || len_io == NULL) return ERR_PADDING;
    len = *len_io;
    if (len == 0 || (len % block_size) != 0) return ERR_PADDING;

    pad = buf[len - 1];
    if (pad == 0 || pad > block_size) return ERR_PADDING;
    if (pad > len) return ERR_PADDING;

    for (i = 0; i < pad; i++) {
        if (buf[len - 1 - i] != (uint8_t) pad) {
            return ERR_PADDING;
        }
    }

    *len_io = len - pad;
    return 0;
}

static int maybe_base64_decode(const uint8_t *in, size_t in_len,
                               uint8_t **out, size_t *out_len) {
    int ret;
    size_t olen = 0;
    uint8_t *buf = NULL;

    *out = NULL;
    *out_len = 0;

    ret = mbedtls_base64_decode(NULL, 0, &olen, in, in_len);
    if (ret == 0 || ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        buf = (uint8_t *) malloc(olen ? olen : 1);
        if (buf == NULL) return ERR_ALLOC;

        ret = mbedtls_base64_decode(buf, olen, &olen, in, in_len);
        if (ret == 0) {
            *out = buf;
            *out_len = olen;
            return 1; /* decoded */
        }

        secure_free(buf, olen ? olen : 1);
    }

    buf = (uint8_t *) malloc(in_len ? in_len : 1);
    if (buf == NULL) return ERR_ALLOC;
    memcpy(buf, in, in_len);
    *out = buf;
    *out_len = in_len;
    return 0; /* raw */
}

static int parse_encrypted_content(const uint8_t **p, const uint8_t *eci_end,
                                   cms_parts_t *out) {
    int ret;
    asn1_view_t v;
    const uint8_t *q, *qend;
    size_t total = 0, off = 0;

    if (*p >= eci_end) return ERR_ASN1;

    if (**p == 0x80) {
        /* primitive [0] IMPLICIT OCTET STRING */
        ret = asn1_get_tlv2(p, eci_end, 0x80, &v);
        if (ret != 0) return ret;
        if (v.indefinite) return ERR_FORMAT;
        out->enc = v.p;
        out->enc_len = v.len;
        return 0;
    }

    if (**p != 0xA0) {
        return ERR_ASN1;
    }

    /* constructed [0] wrapper containing OCTET STRING pieces */
    ret = asn1_get_tlv2(p, eci_end, 0xA0, &v);
    if (ret != 0) return ret;

    ret = asn1_enter_constructed(&v, eci_end, &q, &qend);
    if (ret != 0) return ret;

    {
        const uint8_t *t = q;
        while (t < qend) {
            asn1_view_t part;
            ret = asn1_get_tlv2(&t, qend, 0x04, &part);
            if (ret != 0) return ret;
            if (part.indefinite) return ERR_FORMAT;
            total += part.len;
        }
    }

    out->enc_alloc = (uint8_t *) malloc(total ? total : 1);
    if (out->enc_alloc == NULL) return ERR_ALLOC;

    while (q < qend) {
        asn1_view_t part;
        ret = asn1_get_tlv2(&q, qend, 0x04, &part);
        if (ret != 0) return ret;
        memcpy(out->enc_alloc + off, part.p, part.len);
        off += part.len;
    }

    out->enc = out->enc_alloc;
    out->enc_len = total;
    return 0;
}

static int parse_cms_known_structure(const uint8_t *der, size_t der_len,
                                     cms_parts_t *out) {
    int ret;
    const uint8_t *p = der;
    const uint8_t *global_end = der + der_len;

    asn1_view_t ci, content0, ed, riset, ri, eci, alg;
    const uint8_t *q, *qend;

    memset(out, 0, sizeof(*out));

    /* ContentInfo ::= SEQUENCE */
    ret = asn1_get_tlv2(&p, global_end, 0x30, &ci);
    if (ret != 0) return ret;
    ret = asn1_enter_constructed(&ci, global_end, &p, &global_end);
    if (ret != 0) return ret;

    /* contentType OBJECT IDENTIFIER */
    {
        asn1_view_t oid;
        ret = asn1_get_tlv2(&p, global_end, 0x06, &oid);
        if (ret != 0) return ret;
    }

    /* content [0] EXPLICIT */
    ret = asn1_get_tlv2(&p, global_end, 0xA0, &content0);
    if (ret != 0) return ret;
    ret = asn1_enter_constructed(&content0, global_end, &q, &qend);
    if (ret != 0) return ret;

    /* EnvelopedData ::= SEQUENCE */
    ret = asn1_get_tlv2(&q, qend, 0x30, &ed);
    if (ret != 0) return ret;

    {
        const uint8_t *ed_p, *ed_end;
        ed_p = NULL;
        ed_end = NULL;
        ret = asn1_enter_constructed(&ed, qend, &ed_p, &ed_end);
        if (ret != 0) return ret;
        p = ed_p;
        global_end = ed_end;
    }

    /* version INTEGER */
    {
        asn1_view_t ver;
        ret = asn1_get_tlv2(&p, global_end, 0x02, &ver);
        if (ret != 0) return ret;
    }

    /* Optional originatorInfo [0] */
    if (p < global_end && *p == 0xA0) {
        ret = asn1_skip_any2(&p, global_end);
        if (ret != 0) return ret;
    }

    /* recipientInfos SET */
    ret = asn1_get_tlv2(&p, global_end, 0x31, &riset);
    if (ret != 0) return ret;
    ret = asn1_enter_constructed(&riset, global_end, &q, &qend);
    if (ret != 0) return ret;

    /* first RecipientInfo */
    if (q >= qend) return ERR_FORMAT;

    if (*q == 0x30) {
        ret = asn1_get_tlv2(&q, qend, 0x30, &ri);
        if (ret != 0) return ret;
    } else if ((*q & 0xE0) == 0xA0) {
        /* other RecipientInfo CHOICE variants unsupported in this minimal parser */
        return ERR_FORMAT;
    } else {
        return ERR_ASN1;
    }

    {
        const uint8_t *rp, *rend;
        asn1_view_t tmp;

        ret = asn1_enter_constructed(&ri, qend, &rp, &rend);
        if (ret != 0) return ret;

        /* version INTEGER */
        ret = asn1_get_tlv2(&rp, rend, 0x02, &tmp);
        if (ret != 0) return ret;

        /* rid ANY */
        ret = asn1_skip_any2(&rp, rend);
        if (ret != 0) return ret;

        /* keyEncryptionAlgorithm SEQUENCE */
        ret = asn1_get_tlv2(&rp, rend, 0x30, &tmp);
        if (ret != 0) return ret;

        /* encryptedKey OCTET STRING */
        ret = asn1_get_tlv2(&rp, rend, 0x04, &tmp);
        if (ret != 0) return ret;
        if (tmp.indefinite) return ERR_FORMAT;

        out->wrapped_cek = tmp.p;
        out->wrapped_cek_len = tmp.len;
    }

    /* encryptedContentInfo SEQUENCE */
    ret = asn1_get_tlv2(&p, global_end, 0x30, &eci);
    if (ret != 0) return ret;

    {
        const uint8_t *ep, *eend;
        ep = NULL;
        eend = NULL;
        ret = asn1_enter_constructed(&eci, global_end, &ep, &eend);
        if (ret != 0) return ret;
        p = ep;
        global_end = eend;
    }

    /* contentType OBJECT IDENTIFIER */
    {
        asn1_view_t tmp;
        ret = asn1_get_tlv2(&p, global_end, 0x06, &tmp);
        if (ret != 0) return ret;
    }

    /* contentEncryptionAlgorithm SEQUENCE */
    ret = asn1_get_tlv2(&p, global_end, 0x30, &alg);
    if (ret != 0) return ret;

    {
        const uint8_t *ap, *aend;
        asn1_view_t tmp;

        ret = asn1_enter_constructed(&alg, global_end, &ap, &aend);
        if (ret != 0) return ret;

        /* algorithm OID */
        ret = asn1_get_tlv2(&ap, aend, 0x06, &tmp);
        if (ret != 0) return ret;

        /* parameters = IV OCTET STRING */
        ret = asn1_get_tlv2(&ap, aend, 0x04, &tmp);
        if (ret != 0) return ret;
        if (tmp.indefinite) return ERR_FORMAT;

        out->iv = tmp.p;
        out->iv_len = tmp.len;
    }

    /* encryptedContent [0] */
    if (p >= global_end) return ERR_FORMAT;
    ret = parse_encrypted_content(&p, global_end, out);
    if (ret != 0) return ret;

    if (out->iv_len != 16) return ERR_FORMAT;
    if (out->enc_len == 0) return ERR_FORMAT;

    return 0;
}

/*
 * Returns 0 on success.
 * On success, *pt is malloc'd and must be freed by caller.
 */
int decrypt_kms_ct_for_recipient(const uint8_t *ct, size_t ct_len,
                                 const uint8_t *key_data, size_t key_len,
                                 uint8_t **pt, size_t *pt_len) {
    int ret = 0;
    int parse_ret = 0;
    uint8_t *der = NULL;
    size_t der_len = 0;
    cms_parts_t parts;

    mbedtls_pk_context pk;
    mbedtls_rsa_context *rsa = NULL;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    uint8_t *key_buf = NULL;
    uint8_t *cek = NULL;
    size_t cek_len = 0;
    uint8_t *out = NULL;
    size_t out_len = 0;
    unsigned char iv[16];
    const char *pers = "cms_oaep_decrypt";

    if (ct == NULL || key_data == NULL || pt == NULL || pt_len == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    *pt = NULL;
    *pt_len = 0;
    memset(&parts, 0, sizeof(parts));

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *) pers, strlen(pers));
    if (ret != 0) goto cleanup;

    parse_ret = maybe_base64_decode(ct, ct_len, &der, &der_len);
    if (parse_ret < 0) {
        ret = parse_ret;
        goto cleanup;
    }

    ret = parse_cms_known_structure(der, der_len, &parts);
    if (ret != 0) goto cleanup;

    key_buf = (uint8_t *) malloc(key_len + 1);
    if (key_buf == NULL) {
        ret = ERR_ALLOC;
        goto cleanup;
    }
    memcpy(key_buf, key_data, key_len);
    key_buf[key_len] = '\0';

    ret = mbedtls_pk_parse_key(&pk, key_buf, key_len + 1,
                               NULL, 0,
                               mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ret = mbedtls_pk_parse_key(&pk, key_data, key_len,
                                   NULL, 0,
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) goto cleanup;
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        ret = ERR_FORMAT;
        goto cleanup;
    }

    rsa = mbedtls_pk_rsa(pk);
    if (rsa == NULL) {
        ret = ERR_FORMAT;
        goto cleanup;
    }

    ret = mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    if (ret != 0) goto cleanup;

    cek_len = mbedtls_pk_get_len(&pk);
    cek = (uint8_t *) malloc(cek_len);
    if (cek == NULL) {
        ret = ERR_ALLOC;
        goto cleanup;
    }

    ret = mbedtls_pk_decrypt(&pk,
                             parts.wrapped_cek, parts.wrapped_cek_len,
                             cek, &cek_len, cek_len,
                             mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) goto cleanup;

    if (cek_len != 32) {
        ret = ERR_FORMAT;
        goto cleanup;
    }

    out = (uint8_t *) malloc(parts.enc_len);
    if (out == NULL) {
        ret = ERR_ALLOC;
        goto cleanup;
    }
    memcpy(iv, parts.iv, 16);

    {
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);

        ret = mbedtls_aes_setkey_dec(&aes, cek, 256);
        if (ret == 0) {
            ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT,
                                        parts.enc_len, iv, parts.enc, out);
        }

        mbedtls_aes_free(&aes);
        if (ret != 0) goto cleanup;
    }

    out_len = parts.enc_len;
    ret = pkcs7_unpad(out, &out_len, 16);
    if (ret != 0) goto cleanup;
    out[out_len++] = '\0';

    *pt = out;
    *pt_len = out_len;
    out = NULL;
    ret = 0;

cleanup:
    if (ret != 0) {
        if (out != NULL) secure_free(out, parts.enc_len);
    }

    if (parts.enc_alloc != NULL) {
        secure_free(parts.enc_alloc, parts.enc_len);
    }
    if (cek != NULL) secure_free(cek, cek_len ? cek_len : 32);
    if (key_buf != NULL) secure_free(key_buf, key_len + 1);
    if (der != NULL) secure_free(der, der_len);

    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}