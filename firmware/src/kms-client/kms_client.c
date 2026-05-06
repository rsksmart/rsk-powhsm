/* kms_mbedtls_sigv4.c
 * Compile:
 *   gcc -O2 kms_mbedtls_sigv4.c -o kms_client -lmbedtls -lmbedx509 -lmbedcrypto
 *
 * Fill in REGION and CA_PEM_PATH.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <netdb.h>
#include <errno.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/base64.h>

#include <nsm.h>

#include "kms_decrypt.h"

#include "cJSON.h"

#define REGION            "us-east-2"
#define SERVICE           "kms"
#ifdef USE_TCP
#define CA_PEM_PATH       "/etc/ssl/certs/ca-certificates.crt" /* adjust */
#else
#define CA_PEM_PATH       "/ca-certificates.crt" /* adjust */
#endif
#define AWS_TOKEN_TTL     "21600" /* seconds */

char *G_access_key_id = NULL;
char *G_secret_access_key = NULL;
char *G_session_token = NULL;

static void die(const char *msg) { perror(msg); exit(1); }

static int fd_output = 0;
FILE *file_output;
FILE* standard_output;
FILE* standard_error;

static void DEBUG(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(standard_output, fmt, args);
    va_end(args);
}

static void DEBUG_ERROR(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(standard_error, fmt, args);
    va_end(args);
}

/* Helpers: hex encode */
static void hex_encode(const unsigned char *in, size_t inlen, char *out)
{
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < inlen; ++i) {
        out[i*2] = hex[(in[i] >> 4) & 0xF];
        out[i*2+1] = hex[in[i] & 0xF];
    }
    out[inlen*2] = '\0';
}

/* HMAC-SHA256 via mbedtls */
static int hmac_sha256(const unsigned char *key, size_t keylen,
                       const unsigned char *in, size_t inlen,
                       unsigned char out[32])
{
    int ret = 0;
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return -1;
    ret = mbedtls_md_hmac(md, key, keylen, in, inlen, out);
    return ret;
}

/* SHA256 hash */
static void sha256_hex(const unsigned char *in, size_t inlen, char out_hex[65])
{
    unsigned char buf[32];
    mbedtls_sha256(in, inlen, buf, 0);
    hex_encode(buf, 32, out_hex);
}

/* Derive signing key: kDate, kRegion, kService, kSigning */
static void derive_signing_key(const char *secret,
                               const char *date, const char *region,
                               const char *service,
                               unsigned char out_key[32])
{
    unsigned char k_date[32], k_region[32], k_service[32], k_signing[32];
    char k_secret_prefixed[128];
    snprintf(k_secret_prefixed, sizeof(k_secret_prefixed), "AWS4%s", secret);
    hmac_sha256((unsigned char*)k_secret_prefixed, strlen(k_secret_prefixed),
                (unsigned char*)date, strlen(date), k_date);
    hmac_sha256(k_date, 32, (unsigned char*)region, strlen(region), k_region);
    hmac_sha256(k_region, 32, (unsigned char*)service, strlen(service), k_service);
    hmac_sha256(k_service, 32, (unsigned char*)"aws4_request", strlen("aws4_request"), k_signing);
    memcpy(out_key, k_signing, 32);
}

/* Build canonical request and string-to-sign and compute signature */
static void compute_sigv4(const char *method, const char *uri, const char *host,
                          const char *payload, const char *amz_date, const char *date_yyyymmdd,
                          const char *region, const char *service,
                          char *out_authorization_header, size_t auth_size)
{
    /* Simple canonical headers: host and x-amz-date (and x-amz-target / content-type if used) */
    const char *content_type = "application/x-amz-json-1.1";
    const char *amz_target = "TrentService.Decrypt"; /* adjust for other KMS ops */

    char payload_hash_hex[65];
    sha256_hex((const unsigned char*)payload, strlen(payload), payload_hash_hex);

    /* Canonical URI and query string */
    const char *canonical_uri = "/"; /* KMS root path */
    const char *canonical_query = "";

    /* Canonical headers: lowercase, trimmed, with newline */
    char canonical_headers[1024];
    snprintf(canonical_headers, sizeof(canonical_headers),
             "content-type:%s\nhost:%s\nx-amz-date:%s\nx-amz-target:%s\n",
             content_type, host, amz_date, amz_target);

    /* Signed headers */
    const char *signed_headers = "content-type;host;x-amz-date;x-amz-target";

    /* Canonical request */
    char canonical_request[4096];
    snprintf(canonical_request, sizeof(canonical_request),
             "%s\n" /* method */ "%s\n" /* uri */ "%s\n" /* query */ "%s\n" /* headers */ "%s\n" /* signed headers */ "%s",
             method, canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash_hex);

    /* Hash canonical request */
    char canonical_request_hash_hex[65];
    sha256_hex((const unsigned char*)canonical_request, strlen(canonical_request), canonical_request_hash_hex);

    /* String to sign */
    char credential_scope[256];
    snprintf(credential_scope, sizeof(credential_scope), "%s/%s/%s/aws4_request", date_yyyymmdd, region, service);

    char string_to_sign[2048];
    snprintf(string_to_sign, sizeof(string_to_sign),
             "AWS4-HMAC-SHA256\n%s\n%s\n%s",
             amz_date, credential_scope, canonical_request_hash_hex);

    /* Derive signing key */
    unsigned char signing_key[32];
    derive_signing_key(G_secret_access_key, date_yyyymmdd, region, service, signing_key);

    /* Compute signature */
    unsigned char sig_raw[32];
    hmac_sha256(signing_key, 32, (unsigned char*)string_to_sign, strlen(string_to_sign), sig_raw);
    char sig_hex[65];
    hex_encode(sig_raw, 32, sig_hex);

    /* Authorization header */
    char credential[256];
    snprintf(credential, sizeof(credential), "%s/%s", G_access_key_id, credential_scope);

    snprintf(out_authorization_header, auth_size,
             "AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s",
             credential, signed_headers, sig_hex);
}

#define MAX_HEADERS 5

typedef struct {
    const char *method;
    const char *host;
    const char *uri;
    int header_count;
    char *headers[MAX_HEADERS];
    char *body;
} http_request_t;

http_request_t create_http_request(const char* method, const char* host, const char* uri) {
    http_request_t req;
    req.method = method;
    req.host = host;
    req.uri = uri;
    req.header_count = 0;
    req.body = NULL;
    return req;
}

void add_header(http_request_t *req, const char *header) {
    if (req->header_count < MAX_HEADERS) { // Adjust as needed
        req->headers[req->header_count] = strdup(header);
        req->header_count++;
    }
}

int build_http_request(http_request_t req, char *out_buf, size_t buf_size) {
    // Build the HTTP request string into out_buf based on req fields
    int offset = snprintf(out_buf, buf_size, "%s %s HTTP/1.1\r\nHost: %s\r\n",
                          req.method, req.uri, req.host);
    for (int i = 0; i < req.header_count; i++) {
        offset += snprintf(out_buf + offset, buf_size - offset, "%s\r\n", req.headers[i]);
    }
    offset += snprintf(out_buf + offset, buf_size - offset, "\r\n");
    if (req.body) {
        offset += snprintf(out_buf + offset, buf_size - offset, "%s", req.body);
    }
    return offset;
}

typedef struct {
    int code;
    char *body;
    size_t body_len;
} http_response_t;

typedef int (*read_fn_t)(void *ctx, char *buf, size_t readsize);

static int recv_wrapper(void *ctx, char *buf, size_t readsize) {
    int fd = *(int*)ctx;
    return recv(fd, buf, readsize, 0);
}

static bool parse_http_response(read_fn_t read_fn, void *ctx, http_response_t *resp) {
    /* 
    Simple HTTP response parser: read status code and body.
    Returns false upon any issues reading or parsing.
    Body is dynamically allocated according to content-length
    */
    char line[1024];
    size_t line_len = 0;
    int status_code = 0;
    size_t content_length = 0;
    int headers_done = 0;
    char *body = NULL;
    size_t body_read = 0;

    // Read status line
    line_len = 0;
    while (line_len < sizeof(line) - 1) {
        int c = read_fn(ctx, line + line_len, 1);
        if (c != 1) return false;
        if (line[line_len] == '\n') break;
        line_len++;
    }
    line[line_len] = '\0';
    if (sscanf(line, "HTTP/%*s %d", &status_code) != 1) return false;

    // Read headers
    while (1) {
        line_len = 0;
        while (line_len < sizeof(line) - 1) {
            int c = read_fn(ctx, line + line_len, 1);
            if (c != 1) return false;
            if (line[line_len] == '\n') break;
            line_len++;
        }
        line[line_len] = '\0';
        if (line[0] == '\r' || line[0] == '\n') break; // End of headers

        // Parse Content-Length
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            content_length = strtoul(line + 15, NULL, 10);
        }
    }

    // Read body
    if (content_length > 0) {
        body = malloc(content_length + 1);
        if (!body) return false;
        body_read = 0;
        while (body_read < content_length) {
            int n = read_fn(ctx, body + body_read, content_length - body_read);
            if (n <= 0) { free(body); return false; }
            body_read += n;
        }
        body[content_length] = '\0';
    }

    resp->code = status_code;
    resp->body = body;
    resp->body_len = content_length;
    return true;
}

void free_http_response(http_response_t *resp) {
    if (resp->body) free(resp->body);
}

#ifdef USE_TCP
/* Simple TCP connect (returns fd) */
static int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints, *res, *rp;
    int sfd;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) continue;
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sfd);
    }
    freeaddrinfo(res);
    if (rp == NULL) return -1;
    return sfd;
}
#else
/* Simple VSOCK connect (returns fd) */
static int vsock_connect(unsigned int cid, unsigned int port) {
    struct sockaddr_vm servaddr;
    int sockfd;

    sockfd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sockfd == -1) {
        return -1;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.svm_family = AF_VSOCK;
    servaddr.svm_cid = cid;
    servaddr.svm_port = port;

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}
#endif

static void setup_output() {
#ifdef USE_TCP
    standard_output = stdout;
    standard_error = stderr;
#else
    fd_output = vsock_connect(3, 4333);
    if (!fd_output) {
        die("vsock_connect");
    }
    file_output = fdopen(fd_output, "w");
    if (!file_output) {
        close(fd_output);
        die("fdopen");
    }
    standard_output = file_output;
    standard_error = file_output;
#endif
}

const char *G_crg_host = "169.254.169.254";
#ifdef USE_TCP
    const char *G_crg_port = "80";
#else
    const unsigned int G_crg_cid = 3;
    const unsigned int G_crg_port = 7666;
#endif

static int connect_to_iam_server() {
#ifdef USE_TCP
    /* Connect TCP */
    int sockfd = tcp_connect(G_crg_host, G_crg_port);
    if (sockfd < 0) die("tcp_connect");
#else
    /* Connect TCP */
    int sockfd = vsock_connect(G_crg_cid, G_crg_port);
    if (sockfd < 0) die("vsock_connect");
#endif
    return sockfd;
}

static void load_credentials() {
    int sockfd;
    char request_buffer[1024];
    int request_len;
    http_request_t request;
    http_response_t response;

    char* token = NULL;
    char *token_header = NULL;
    char* role = NULL;
    char *credentials_path = NULL;
    char *credentials_json = NULL;

    // Request token
    sockfd = connect_to_iam_server();
    request = create_http_request("PUT", G_crg_host, "/latest/api/token");
    add_header(&request, "X-aws-ec2-metadata-token-ttl-seconds: " AWS_TOKEN_TTL);
    request_len = build_http_request(request, request_buffer, sizeof(request_buffer));
    if (send(sockfd, request_buffer, request_len, 0) != request_len) {
        close(sockfd);
        die("token request");
    }
    if (!parse_http_response(recv_wrapper, &sockfd, &response)) {
        close(sockfd);
        die("token response");
    }
    if (response.code != 200) {
        free_http_response(&response);
        close(sockfd);
        die("token response code");
    }
    token = strdup(response.body);
    free_http_response(&response);
    close(sockfd);

    // Request role
    sockfd = connect_to_iam_server();
    request = create_http_request("GET", G_crg_host, "/latest/meta-data/iam/security-credentials/");
    token_header = malloc(strlen("X-aws-ec2-metadata-token:") + strlen(token) + 1);
    sprintf(token_header, "X-aws-ec2-metadata-token: %s", token);
    add_header(&request, token_header);
    request_len = build_http_request(request, request_buffer, sizeof(request_buffer));
    if (send(sockfd, request_buffer, request_len, 0) != request_len) {
        close(sockfd);
        die("role request");
    }
    if (!parse_http_response(recv_wrapper, &sockfd, &response)) {
        close(sockfd);
        die("role response");
    }
    if (response.code != 200) {
        free_http_response(&response);
        close(sockfd);
        die("role response code");
    }
    role = strdup(response.body);
    free_http_response(&response);
    close(sockfd);

    // Request credentials for role
    sockfd = connect_to_iam_server();
    credentials_path = malloc(strlen("/latest/meta-data/iam/security-credentials/") + strlen(role) + 1);
    sprintf(credentials_path, "/latest/meta-data/iam/security-credentials/%s", role);
    request = create_http_request("GET", G_crg_host, credentials_path);
    add_header(&request, token_header);
    request_len = build_http_request(request, request_buffer, sizeof(request_buffer));
    if (send(sockfd, request_buffer, request_len, 0) != request_len) {
        close(sockfd);
        die("credentials request");
    }
    if (!parse_http_response(recv_wrapper, &sockfd, &response)) {
        close(sockfd);
        die("credentials response");
    }
    if (response.code != 200) {
        free_http_response(&response);
        close(sockfd);
        die("credentials response code");
    }
    credentials_json = strdup(response.body);
    free_http_response(&response);
    close(sockfd);

    cJSON *json = cJSON_Parse(credentials_json);
    if (!json) {
        die("credentials JSON parsing");
    }
    DEBUG("Credentials JSON:\n%s\n", credentials_json);
    cJSON *akid = cJSON_GetObjectItemCaseSensitive(json, "AccessKeyId");
    cJSON *sakey = cJSON_GetObjectItemCaseSensitive(json, "SecretAccessKey");
    cJSON *stoken = cJSON_GetObjectItemCaseSensitive(json, "Token");
    if (!cJSON_IsString(akid) || !cJSON_IsString(sakey) || !cJSON_IsString(stoken)) {
        DEBUG_ERROR("Missing AccessKeyId, SecretAccessKey, or SessionToken in credentials JSON\n");
        cJSON_Delete(json);
        exit(1);
    }
    G_access_key_id = strdup(akid->valuestring);
    G_secret_access_key = strdup(sakey->valuestring);
    G_session_token = strdup(stoken->valuestring);
    cJSON_Delete(json);

    DEBUG("Access key id: %s\n", G_access_key_id);
    DEBUG("Secret access key: %s\n", G_secret_access_key);
    DEBUG("Session token: %s\n", G_session_token);

    free(credentials_json);
    free(credentials_path);
    free(token_header);
    free(role);
    free(token);
}

static void free_credentials() {
    free(G_access_key_id);
    free(G_secret_access_key);
    free(G_session_token);
}

static void DEBUG_HEX(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        DEBUG("%02x", data[i]);
    }
    DEBUG("\n");
}

/* Maximum size of the attestation document */
#define NSM_MAX_ATTESTATION_DOC_SIZE (16 * 1024)

#ifndef USE_TCP
static void get_attestation(
    uint8_t* pub_der,
    uint32_t pub_der_len,
    uint8_t *att_doc,
    uint32_t *att_doc_len) {
    DEBUG("Getting attestation document from NSM...\n");

    int nsm_fd = nsm_lib_init();
    if (nsm_fd < 0) {
        DEBUG("NSM lib init failed\n");
        return;
    }

    /* Get the attestation document. */
    int rc = nsm_get_attestation_doc(nsm_fd, NULL, 0, NULL, 0, pub_der, pub_der_len, att_doc, att_doc_len);
    if (rc) {
        nsm_lib_exit(nsm_fd);
        DEBUG("Failed to get attestation document: %d\n", rc);
        return;
    }

    DEBUG("Attestation document:\n");
    DEBUG_HEX(att_doc, *att_doc_len);

    nsm_lib_exit(nsm_fd);
}
#endif

static bool generate_rsa_keypair(
    mbedtls_ctr_drbg_context *ctr_drbg,
    mbedtls_pk_context *pk,
    unsigned char *pub_der,
    size_t pub_der_size,
    unsigned char **pub_start,
    uint32_t *pub_len) {

    mbedtls_pk_init(pk);
    *pub_start = NULL;

    if (mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
        DEBUG_ERROR("pk_setup failed\n");
        return false;
    }

    if (mbedtls_rsa_gen_key(
            mbedtls_pk_rsa(*pk),
            mbedtls_ctr_drbg_random,
            ctr_drbg,
            2048,
            65537
        ) != 0) {
        DEBUG_ERROR("rsa_gen_key failed\n");
        return false;
    }

    unsigned char pri_der[2048]; /* should be enough for 2048-bit RSA private key */
    unsigned char *pri_der_start;
    uint32_t pri_der_len;
    memset(pri_der, 0, sizeof(pri_der));
    pri_der_len = mbedtls_pk_write_key_der(pk, pri_der, sizeof(pri_der));
    if (pri_der_len < 0) {
        DEBUG_ERROR("pk_write_key_der failed\n");
        return false;
    }
    pri_der_start = pri_der + sizeof(pri_der) - pri_der_len;
    DEBUG("RSA private key:\n");
    DEBUG_HEX(pri_der_start, pri_der_len);
    DEBUG("================\n");

    memset(pub_der, 0, pub_der_size);
    *pub_len = mbedtls_pk_write_pubkey_der(pk, pub_der, pub_der_size);
    if (*pub_len < 0) {
        DEBUG_ERROR("pk_write_pubkey_der failed\n");
        return false;
    }

    *pub_start = pub_der + pub_der_size - *pub_len;
    return true;
}

void parse_hex(char* hex_str, uint8_t* out_buf, size_t out_buf_size, size_t* out_len) {
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0 || hex_len / 2 > out_buf_size) {
        *out_len = 0;
        return;
    }
    for (size_t i = 0; i < hex_len / 2; i++) {
        sscanf(hex_str + i*2, "%2hhx", &out_buf[i]);
    }
    *out_len = hex_len / 2;
}

int main(void)
{
    uint8_t ct[] = "MIAGCSqGSIb3DQEHA6CAMIACAQIxggFrMIIBZwIBAoAgG23bE5ekDf9hvsOnh9/mDsP32NIWbAEDt9nxA4/BhWYwPAYJKoZIhvcNAQEHMC+gDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAASCAQBA4L9kALB1lQvL9JQd7l3wE+XsrFgORQciI9RIorF5xslB3KSr0en7S7GTmgTgPRAf4TTyeQQ2cwF4Ow2KfGcllNkEqH0eSR0dNV0yz19xYroEPBGgIPGlLOHiLWY1S5oIRtNed3SE2vV6E4NEwz8sr0EosFdFAZTcEwJYBRYSw/ul/1n/pQDulobv0U4zfqlUGSc67Z36DaxW2gWjTM1RmSOiczqJFMMrWQ6XZTU5SbU1pJluIM5XIX4lKsLSJTvuhSOvuJ9IVrBjBGuNyJqQbA+wUGGz5ck857Ivh167zbz3NaBL69Y4BLo81UF3HXMcSVOnZMNagui4MSJ1Jm1WMIAGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEJLJ9TmJnWZCr/XnMgXwS8eggAQwE+V4TGpgSr461NUy6Ii/ztZhROl5V9saBN4YSgOqcAvihuOWFGyeGK76+HKEztTKAAAAAAAAAAAAAA==";
    char hex_key_data[] = "308204a40201000282010100b1ff9ea2b7133b319ec92b645bdf2f35fad982c3e56a5e6037ec04abaf67a00ef93ef63d4a7af38319ccb37198c40dfad885c06a11ab563d79f592ebfe2aafe235a2417f66fbe0916825be663854392f283d335048eb6365376a82947afb4f82d8299695f869100e139f6a2f53958b638dbc454b1d7bde3fdfc87dd7faadcb50ddbefaa51c1774ac8891b8728ca2e4e782837c19198b8fd7840615d1dbca68f4f25b17530d1215a4489d9f330df53ccb75b999a786c5521b5f3f2bbf6c4e662972bb60cfc42e69d5c1c7f687075726c81b2c4c4c38f6f750455ec5818cdb7f1fbc5cd9950e7cdf30a5fb6a970df794a32caa8635e2171bf38735447e1499c9c102030100010282010011b58a00ff5682fad9be8306face302f2b2dda343a4177a5473b0ca2b62c22743e1f6e9c7776d717fe886b7bff84092e07be2e19b2ab565e17a1b36aafe705221f4e20704b2fff816e6518890f336f8fd76d8b57b59b24ea25f5fe8ade3ddd9e937a109271c2d960c527380766c5fb0357e925a0f372e69046e7f67faa60018c914485784559d589c50bc2f297b7dc43e7d3fb1b1765db9d398b0b1e4a4f85125cb2497cfe48dff6a3833d4ac7cd12d7ebb8e835178ef5174f7f42e863848472cef1924251926bbdcd91fa42ec71d94bf3da10c84aa4356079d83d7f2a5d99667916d5c5639a152c5fc1768d75eda2aed6e730a15cff63402364ddae0869ecef02818100e162756370dc9d0c4f16d90f919f90e0dcfa3ad0bdad925719a5b538bc3a4f72c0684f2b4c97749f92adad9ad4222a01dd5505c4eef4e209e8960b33c50fbdf31360cb4c07965550206e58037176d017cb97c620de18917dd24ddbca3262f2d17b5e3e75e2a319af74ae845c9f111cdec808f0adb9d65b78ab775460d15f9a5f02818100ca2d5a872a6c3dfe5811592fdfe07fe30a4971f0ee1ab860ac83b9f7086de8353f2c7e60fb31522e05ea3211e5286655537ead89f8e1346225bb22ec3ea28573e6778a270eba86314079cd0f1e5117f1ae2053ae1bb63e6855d1b515d5bf419f62a2486d5cd4c43dfb95a7c8f8807f03114be3ba57406082c394776e4ab14fdf0281807da9a3c1b9df8740a1a81f85eaaf88db96d97d897cf815abb2850db180611282ec7c3c07ec4055a9d2e23af5246997fa4a29697a0fb141863cc3cba325b04d3c0605e5d392376381b55350873aefffbe04a9aeb20ca2ae1bf4f1ac25e449ff1085345aa6e7a200642f2e4e6645da08babdd51e3bfe6d61bab9ff627048cc810902818100aeda9ab8dbcfd1adefacd15dbe5a0340f0dca456a31728ef334499c934d9194333e7df4530fa6f00aecce590e488143927851fc17c26098ff8e1e84a39c18579bf911342c4523d4ccb5e8c22cf2d836fda10cb4e8159149057e88e9cdbc815912b54ff1ed6728d66adf7b8acef7ef25a4cd33d99236ce20b35eb697f51ca1831028181009f53c704b024d9e6b34d7e04af8510d30500ecac0eec8e6e67d7be4d302662864cc3b18e0208a6e068f59150700f4208fbd61b74d29170fc4b296e913ed7b5a24ee2ac2d9a6f63f98d963432fd181f4b3cbbc17a0528f9659712589c02321b2247e9d776a22a0ec3141ed0be30d6e1cc9e970aac6f46302a7f56a05501141bc6";
    uint8_t key_data[2048];
    size_t key_data_len;
    parse_hex(hex_key_data, key_data, sizeof(key_data), &key_data_len);

    uint8_t *plaintext;
    size_t plaintext_len;
    int decrypt_res;
    if (decrypt_res = decrypt_kms_ct_for_recipient(ct, strlen(ct), key_data, key_data_len, &plaintext, &plaintext_len)) {
        printf("Decrypt error: 0x%x\n", -decrypt_res);
        return 1;
    }

    printf("Plaintext: %s\n", plaintext);
    free(plaintext);

    return 0;

    setup_output();

    /* ---------------- mbedTLS init ---------------- */
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    char errbuf[200];

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              NULL, 0) != 0) { DEBUG_ERROR("DRBG seed failed\n"); return 1; }

    mbedtls_pk_context pk;
    unsigned char pub_der[2048]; /* should be enough for 2048-bit RSA public key */
    unsigned char *pub_der_start;
    uint32_t pub_der_len;
    if (!generate_rsa_keypair(&ctr_drbg, &pk, pub_der, sizeof(pub_der), &pub_der_start, &pub_der_len)) {
        DEBUG_ERROR("RSA key generation failed\n");
        return 1;
    }
    DEBUG("RSA public key:\n");
    DEBUG_HEX(pub_der_start, pub_der_len);
    DEBUG("==============\n");

#ifndef USE_TCP
    uint8_t att_doc[NSM_MAX_ATTESTATION_DOC_SIZE];
    uint32_t att_doc_len = NSM_MAX_ATTESTATION_DOC_SIZE;
    get_attestation(pub_der_start, pub_der_len, att_doc, &att_doc_len);
    char att_doc_base64[NSM_MAX_ATTESTATION_DOC_SIZE * 2]; /* should be enough for base64 encoding */
    size_t att_doc_base64_len;
    if (mbedtls_base64_encode((unsigned char *)att_doc_base64, sizeof(att_doc_base64), &att_doc_base64_len, att_doc, att_doc_len)) {
        DEBUG_ERROR("Base64 encoding failed (size calculation)\n");
        return 1;
    }
#endif

    /* Build the KMS JSON payload */
    cJSON *kmsPayload = cJSON_CreateObject();
    cJSON_AddStringToObject(kmsPayload, "KeyId", "arn:aws:kms:us-east-2:192930478100:key/e4548bc2-cfa6-40f1-b9e9-960779369798");
    cJSON_AddStringToObject(kmsPayload, "CiphertextBlob", "AQICAHgg1zChhefCtdF3Qt8+NrIkNAL2NUqFpqR2t9HRIZwuvAHbJfpxxkMMVmp4k33oqo0JAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM25+5kcLVN49RiuWuAgEQgDsN8D61wLuR6A0eXU5rNHw7GuzBR6rusNVByZE8gTX2GzPlwoNmsSDUR1i9eDFxE9FAAqlg0QvKnpggeA==");
#ifndef USE_TCP
    cJSON *recipient = cJSON_CreateObject();
    cJSON_AddStringToObject(recipient, "KeyEncryptionAlgorithm", "RSAES_OAEP_SHA_256");
    cJSON_AddStringToObject(recipient, "AttestationDocument", att_doc_base64);
    cJSON_AddItemToObject(kmsPayload, "Recipient", recipient);
#endif

    const char *payload = cJSON_PrintUnformatted(kmsPayload);
    cJSON_Delete(kmsPayload);
    DEBUG("KMS request payload:\n%s====================\n", payload);

    load_credentials();

    const char *kms_host = "kms." REGION ".amazonaws.com";
#ifdef USE_TCP
    const char *kms_port = "443";
#else
    const unsigned int kms_cid = 3;
    const unsigned int kms_port = 8777;
#endif

    /* Time for x-amz-date and date scope */
    time_t now = time(NULL);
    struct tm gmt;
    gmtime_r(&now, &gmt);
    char amz_date[17]; /* YYYYMMDD'T'HHMMSS'Z' */
    char date_yyyymmdd[9];
    strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", &gmt);
    strftime(date_yyyymmdd, sizeof(date_yyyymmdd), "%Y%m%d", &gmt);

    /* Compute SigV4 Authorization header */
    char authorization[1024];
    compute_sigv4("POST", "/", kms_host, payload, amz_date, date_yyyymmdd, REGION, SERVICE, authorization, sizeof(authorization));

    /* Build HTTP request */
    char http_req[32*1024];
    snprintf(http_req, sizeof(http_req),
        "POST / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/x-amz-json-1.1\r\n"
        "X-Amz-Date: %s\r\n"
        "X-Amz-Target: TrentService.Decrypt\r\n"
        "X-Amz-Security-Token: %s\r\n"
        "Accept: application/json\r\n"
        "Authorization: %s\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s",
        kms_host, amz_date, G_session_token, authorization, strlen(payload), payload);

    /* Load CA */
    if (mbedtls_x509_crt_parse_file(&cacert, CA_PEM_PATH) != 0) {
        DEBUG_ERROR("Failed to load CA file: %s\n", CA_PEM_PATH);
        return 1;
    }

    if (mbedtls_ssl_config_defaults(&conf,
                MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_STREAM,
                MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        DEBUG_ERROR("ssl_config_defaults failed\n");
        return 1;
    }
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    if (mbedtls_ssl_setup(&ssl, &conf) != 0) {
        DEBUG_ERROR("ssl_setup failed\n");
        return 1;
    }

    /* SNI: set server hostname for cert verification and SNI extension */
    if (mbedtls_ssl_set_hostname(&ssl, kms_host) != 0) {
        DEBUG_ERROR("ssl_set_hostname failed\n");
        return 1;
    }

#ifdef USE_TCP
    /* Connect TCP and hand off socket to mbedtls net layer */
    int sockfd = tcp_connect(kms_host, kms_port);
    if (sockfd < 0) die("tcp_connect");
#else
    /* Connect TCP and hand off socket to mbedtls net layer */
    int sockfd = vsock_connect(kms_cid, kms_port);
    if (sockfd < 0) die("vsock_connect");
#endif
    mbedtls_net_context server_fd;
    mbedtls_net_init(&server_fd);
    server_fd.fd = sockfd;

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    /* Perform TLS handshake */
    int ret;
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            DEBUG_ERROR("ssl_handshake error: %s\n", errbuf);
            return 1;
        }
    }

    /* Verify certificate */
    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        char vrfybuf[512];
        mbedtls_x509_crt_verify_info(vrfybuf, sizeof(vrfybuf), "  ! ", flags);
        DEBUG_ERROR("Certificate verification failed: %s\n", vrfybuf);
        return 1;
    }

    /* Send HTTP request (no ALPN; using HTTP/1.1) */
    size_t written = 0;
    size_t req_len = strlen(http_req);
    DEBUG("=== Request ===\n%s\n", http_req);
    while (written < req_len) {
        ret = mbedtls_ssl_write(&ssl, (const unsigned char*)http_req + written, req_len - written);
        if (ret > 0) written += ret;
        else if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        else { mbedtls_strerror(ret, errbuf, sizeof(errbuf)); DEBUG_ERROR("ssl_write error: %s\n", errbuf); break; }
    }

    /* Read response (simple) */
    unsigned char buf[4096];
    int first = 1;
    int done = 0;
    while (!done) {
        ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf)-1);
        if (ret > 0) {
            if (first)
                DEBUG("=== Response ===\n");

            buf[ret] = '\0';
            DEBUG("%s", buf);
            fflush(stdout);
        } else if (ret == 0) {
            if (first)
                DEBUG("Connection closed by server\n");
            else
                DEBUG("\n");
            done = 1;
        } else {
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            DEBUG_ERROR("ssl_read error: %s\n", errbuf);
            done = 1;
        }
        first = 0;
    }

    /* Cleanup */
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&pk);
    free_credentials();

#ifndef USE_TCP
    fflush(file_output);
    fclose(file_output);
    close(fd_output);
#endif

    return 0;
}