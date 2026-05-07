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
                          const char *region, const char *service, const char *target,
                          char *out_authorization_header, size_t auth_size)
{
    /* Simple canonical headers: host and x-amz-date (and x-amz-target / content-type if used) */
    const char *content_type = "application/x-amz-json-1.1";

    char payload_hash_hex[65];
    sha256_hex((const unsigned char*)payload, strlen(payload), payload_hash_hex);

    /* Canonical URI and query string */
    const char *canonical_uri = "/"; /* KMS root path */
    const char *canonical_query = "";

    /* Canonical headers: lowercase, trimmed, with newline */
    char canonical_headers[1024];
    snprintf(canonical_headers, sizeof(canonical_headers),
             "content-type:%s\nhost:%s\nx-amz-date:%s\nx-amz-target:%s\n",
             content_type, host, amz_date, target);

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

static int ssl_read_wrapper(void *ctx, char *buf, size_t readsize) {
    mbedtls_ssl_context *ssl = (mbedtls_ssl_context*)ctx;
    return mbedtls_ssl_read(ssl, buf, readsize);
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
    resp->body = NULL;
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

static bool setup_output() {
#ifdef USE_TCP
    standard_output = stdout;
    standard_error = stderr;
#else
    fd_output = vsock_connect(3, 4333);
    if (!fd_output) {
        DEBUG_ERROR("vsock_connect");
        return false;
    }
    file_output = fdopen(fd_output, "w");
    if (!file_output) {
        close(fd_output);
        DEBUG_ERROR("fdopen");
        return false;
    }
    standard_output = file_output;
    standard_error = file_output;
#endif
    return true;
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

static bool load_credentials() {
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
        DEBUG_ERROR("token request");
        return false;
    }
    if (!parse_http_response(recv_wrapper, &sockfd, &response)) {
        close(sockfd);
        DEBUG_ERROR("token response");
        return false;
    }
    if (response.code != 200) {
        free_http_response(&response);
        close(sockfd);
        DEBUG_ERROR("token response code");
        return false;
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
        DEBUG_ERROR("role request");
        return false;
    }
    if (!parse_http_response(recv_wrapper, &sockfd, &response)) {
        close(sockfd);
        DEBUG_ERROR("role response");
        return false;
    }
    if (response.code != 200) {
        free_http_response(&response);
        close(sockfd);
        DEBUG_ERROR("role response code");
        return false;
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
        DEBUG_ERROR("credentials request");
        return false;
    }
    if (!parse_http_response(recv_wrapper, &sockfd, &response)) {
        close(sockfd);
        DEBUG_ERROR("credentials response");
        return false;
    }
    if (response.code != 200) {
        free_http_response(&response);
        close(sockfd);
        DEBUG_ERROR("credentials response code");
        return false;
    }
    credentials_json = strdup(response.body);
    free_http_response(&response);
    close(sockfd);

    cJSON *json = cJSON_Parse(credentials_json);
    if (!json) {
        DEBUG_ERROR("credentials JSON parsing");
        return false;
    }
    DEBUG("\n=== Credentials JSON ===\n%s\n", credentials_json);
    cJSON *akid = cJSON_GetObjectItemCaseSensitive(json, "AccessKeyId");
    cJSON *sakey = cJSON_GetObjectItemCaseSensitive(json, "SecretAccessKey");
    cJSON *stoken = cJSON_GetObjectItemCaseSensitive(json, "Token");
    if (!cJSON_IsString(akid) || !cJSON_IsString(sakey) || !cJSON_IsString(stoken)) {
        DEBUG_ERROR("Missing AccessKeyId, SecretAccessKey, or SessionToken in credentials JSON\n");
        cJSON_Delete(json);
        return false;
    }
    G_access_key_id = strdup(akid->valuestring);
    G_secret_access_key = strdup(sakey->valuestring);
    G_session_token = strdup(stoken->valuestring);
    cJSON_Delete(json);

    DEBUG("\n=== Loaded Credentials ===\n");
    DEBUG("Access key id: %s\n", G_access_key_id);
    DEBUG("Secret access key: %s\n", G_secret_access_key);
    DEBUG("Session token: %s\n", G_session_token);

    free(credentials_json);
    free(credentials_path);
    free(token_header);
    free(role);
    free(token);

    return true;
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

uint8_t G_att_doc[NSM_MAX_ATTESTATION_DOC_SIZE];
uint32_t G_att_doc_len = NSM_MAX_ATTESTATION_DOC_SIZE;
char G_att_doc_base64[NSM_MAX_ATTESTATION_DOC_SIZE * 2]; /* should be enough for base64 encoding */
size_t G_att_doc_base64_len;

#ifndef USE_TCP
static void get_attestation(
    uint8_t* pub_der,
    uint32_t pub_der_len,
    uint8_t *att_doc,
    uint32_t *att_doc_len) {

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

    DEBUG("\n=== Attestation document ===\n");
    DEBUG_HEX(att_doc, *att_doc_len);

    nsm_lib_exit(nsm_fd);
}
#endif

static bool generate_rsa_keypair(
    mbedtls_ctr_drbg_context *ctr_drbg,
    mbedtls_pk_context *pk,
    unsigned char *pri_der,
    size_t pri_der_size,
    unsigned char** pri_der_start,
    uint32_t *pri_len,
    unsigned char *pub_der,
    size_t pub_der_size,
    unsigned char **pub_der_start,
    uint32_t *pub_len) {

    mbedtls_pk_init(pk);
    *pri_der_start = NULL;
    *pub_der_start = NULL;

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

    memset(pri_der, 0, pri_der_size);
    *pri_len = mbedtls_pk_write_key_der(pk, pri_der, pri_der_size);
    if (*pri_len < 0) {
        DEBUG_ERROR("pk_write_key_der failed\n");
        return false;
    }
    *pri_der_start = pri_der + pri_der_size - *pri_len;
    DEBUG("RSA private key:\n");
    DEBUG_HEX(*pri_der_start, *pri_len);
    DEBUG("================\n");

    memset(pub_der, 0, pub_der_size);
    *pub_len = mbedtls_pk_write_pubkey_der(pk, pub_der, pub_der_size);
    if (*pub_len < 0) {
        DEBUG_ERROR("pk_write_pubkey_der failed\n");
        return false;
    }

    *pub_der_start = pub_der + pub_der_size - *pub_len;
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

mbedtls_ctr_drbg_context G_ctr_drbg;
mbedtls_entropy_context G_entropy;

static bool mbedtls_ctr_drbg_init_global() {
    mbedtls_ctr_drbg_init(&G_ctr_drbg);
    mbedtls_entropy_init(&G_entropy);
    if (mbedtls_ctr_drbg_seed(&G_ctr_drbg, mbedtls_entropy_func, &G_entropy,
                              NULL, 0) != 0) {
        DEBUG_ERROR("mbedtls DRBG seed failed");
        return false;
    }

    return true;
}

static bool do_kms_request(int sockfd,
                           const char* kms_host,
                           const char* target,
                           const char* payload,
                           http_response_t *kms_response) {
    bool fn_ret = true;

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
    compute_sigv4("POST", "/", kms_host, payload,
                  amz_date, date_yyyymmdd, REGION,
                  SERVICE, target, authorization,
                  sizeof(authorization));

    /* Build HTTP request */
    char http_req[32*1024];
    snprintf(http_req, sizeof(http_req),
        "POST / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/x-amz-json-1.1\r\n"
        "X-Amz-Date: %s\r\n"
        "X-Amz-Target: %s\r\n"
        "X-Amz-Security-Token: %s\r\n"
        "Accept: application/json\r\n"
        "Authorization: %s\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s",
        kms_host, amz_date, target, G_session_token, authorization, strlen(payload), payload);

    mbedtls_ssl_context ssl;
    mbedtls_ssl_config ssl_conf;
    mbedtls_x509_crt cacert;
    char errbuf[200];

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&ssl_conf);
    mbedtls_x509_crt_init(&cacert);

    /* Load CA */
    if (mbedtls_x509_crt_parse_file(&cacert, CA_PEM_PATH) != 0) {
        DEBUG_ERROR("Failed to load CA file: %s\n", CA_PEM_PATH);
        fn_ret = false;
        goto cleanup;
    }

    if (mbedtls_ssl_config_defaults(&ssl_conf,
                MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_STREAM,
                MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        DEBUG_ERROR("ssl_config_defaults failed\n");
        fn_ret = false;
        goto cleanup;
    }
    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&ssl_conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &G_ctr_drbg);

    if (mbedtls_ssl_setup(&ssl, &ssl_conf) != 0) {
        DEBUG_ERROR("ssl_setup failed\n");
        fn_ret = false;
        goto cleanup;
    }

    /* SNI: set server hostname for cert verification and SNI extension */
    if (mbedtls_ssl_set_hostname(&ssl, kms_host) != 0) {
        DEBUG_ERROR("ssl_set_hostname failed\n");
        fn_ret = false;
        goto cleanup;
    }

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
            fn_ret = false;
            goto cleanup;
        }
    }

    /* Verify certificate */
    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        char vrfybuf[512];
        mbedtls_x509_crt_verify_info(vrfybuf, sizeof(vrfybuf), "  ! ", flags);
        DEBUG_ERROR("Certificate verification failed: %s\n", vrfybuf);
        fn_ret = false;
        goto cleanup;
    }

    /* Send HTTP request (no ALPN; using HTTP/1.1) */
    size_t written = 0;
    size_t req_len = strlen(http_req);
    DEBUG("\n=== Request ===\n%s\n", http_req);
    while (written < req_len) {
        ret = mbedtls_ssl_write(&ssl, (const unsigned char*)http_req + written, req_len - written);
        if (ret > 0) written += ret;
        else if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        else { mbedtls_strerror(ret, errbuf, sizeof(errbuf)); DEBUG_ERROR("ssl_write error: %s\n", errbuf); break; }
    }

    if (!parse_http_response(ssl_read_wrapper, &ssl, kms_response)) {
        DEBUG_ERROR("KMS response\n");
        fn_ret = false;
        goto cleanup;
    }

cleanup:
    if (!fn_ret) free_http_response(kms_response);
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&ssl_conf);
    return fn_ret;
}

static bool perform_kms_operation(const char* name, cJSON* request, const char* target,
                                  cJSON **kms_response_json) {
    bool fn_ret = true;
    *kms_response_json = NULL;

    const char *kms_host = "kms." REGION ".amazonaws.com";
#ifdef USE_TCP
    const char *kms_port = "443";
    /* Connect TCP and hand off socket to mbedtls net layer */
    int sockfd = tcp_connect(kms_host, kms_port);
    if (sockfd < 0) {
        fn_ret = false;
        DEBUG_ERROR("tcp_connect");
        goto cleanup;
    }
#else
    const unsigned int kms_cid = 3;
    const unsigned int kms_port = 8777;
    /* Connect TCP and hand off socket to mbedtls net layer */
    int sockfd = vsock_connect(kms_cid, kms_port);
    if (sockfd < 0) {
        fn_ret = false;
        DEBUG_ERROR("vsock_connect");
        goto cleanup;
    }
#endif

    http_response_t kms_response;
#ifndef USE_TCP
    cJSON* recipient = cJSON_CreateObject();
    cJSON_AddStringToObject(recipient, "KeyEncryptionAlgorithm", "RSAES_OAEP_SHA_256");
    cJSON_AddStringToObject(recipient, "AttestationDocument", G_att_doc_base64);
    cJSON_AddItemToObject(request, "Recipient", recipient);
#endif
    char* request_str = cJSON_PrintUnformatted(request);
    DEBUG("\n=== %s request ===\n%s\n", name, request_str);
    if (!do_kms_request(sockfd, kms_host, target, request_str, &kms_response)) {
        fn_ret = false;
        DEBUG_ERROR("KMS request failed\n");
        goto cleanup;
    }

    if (kms_response.code != 200) {
        fn_ret = false;
        DEBUG_ERROR("KMS response code: %d\n", kms_response.code);
        DEBUG_ERROR("KMS response body:\n%s\n", kms_response.body);
        goto cleanup;
    }

    *kms_response_json = cJSON_Parse(kms_response.body);
    char* response_str = cJSON_PrintUnformatted(*kms_response_json);
    DEBUG("\n=== %s response ===\n%s\n", name, response_str);
    if (!*kms_response_json) {
        fn_ret = false;
        DEBUG_ERROR("KMS response JSON parsing failed\n");
        goto cleanup;
    }

cleanup:
    if (!fn_ret && *kms_response_json) cJSON_Delete(*kms_response_json);
    free_http_response(&kms_response);
    if (sockfd) close(sockfd);
    if (request_str) free(request_str);
    if (response_str) free(response_str);
    return fn_ret;
}

int main(void)
{
    if (!setup_output()) {
        DEBUG_ERROR("Output setup failed\n");
        return 1;
    }

    if (!load_credentials()) {
        DEBUG_ERROR("Credential loading failed\n");
        return 1;
    }

    if (!mbedtls_ctr_drbg_init_global()) {
        DEBUG_ERROR("mbedtls CTR_DRBG initialization failed\n");
        return 1;
    }

#ifndef USE_TCP
    // Generate ephemeral RSA key pair
    mbedtls_pk_context pk;
    unsigned char pri_der[2048]; /* should be enough for 2048-bit RSA private key */
    unsigned char pub_der[2048]; /* should be enough for 2048-bit RSA public key */
    unsigned char *pub_der_start;
    unsigned char *pri_der_start;
    uint32_t pub_der_len;
    uint32_t pri_der_len;
    if (!generate_rsa_keypair(&G_ctr_drbg, &pk, pri_der, sizeof(pri_der), &pri_der_start, &pri_der_len, pub_der, sizeof(pub_der), &pub_der_start, &pub_der_len)) {
        DEBUG_ERROR("RSA key generation failed\n");
        return 1;
    }
    DEBUG("\n=== Ephemeral RSA private key ===\n");
    DEBUG_HEX(pri_der_start, pri_der_len);
    DEBUG("\n=== Ephemeral RSA public key ===\n");
    DEBUG_HEX(pub_der_start, pub_der_len);

    // Generate attestation document
    get_attestation(pub_der_start, pub_der_len, G_att_doc, &G_att_doc_len);
    if (mbedtls_base64_encode((unsigned char *)G_att_doc_base64, sizeof(G_att_doc_base64), &G_att_doc_base64_len, G_att_doc, G_att_doc_len)) {
        DEBUG_ERROR("Base64 encoding failed (size calculation)\n");
        return false;
    }
#else
    unsigned char *pub_der_start = NULL;
    uint32_t pub_der_len = 0;
#endif

    // Generate random text to encrypt
    srand((unsigned int)time(NULL));
    char random_plaintext[128];
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (size_t i = 0; i < sizeof(random_plaintext) - 1; i++) {
        random_plaintext[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    random_plaintext[sizeof(random_plaintext) - 1] = '\0';
    DEBUG("\n=== Random plaintext to encrypt ===\n%s\n", random_plaintext);

#define KMS_KEY_ID "arn:aws:kms:us-east-2:192930478100:key/e4548bc2-cfa6-40f1-b9e9-960779369798"

    // ************* BEGIN DESCRIBE ************* // 
    cJSON *kms_describe_request = cJSON_CreateObject();
    cJSON *kms_describe_response;
    cJSON_AddStringToObject(kms_describe_request, "KeyId", KMS_KEY_ID);

    if (!perform_kms_operation("Describe key", kms_describe_request, "TrentService.DescribeKey", &kms_describe_response)) {
        DEBUG_ERROR("KMS Describe operation failed\n");
        return 1;
    }

    cJSON_Delete(kms_describe_request);
    cJSON_Delete(kms_describe_response);
    // ************* END DESCRIBE ************* //

    // ************* BEGIN POLICY READ ************* // 
    cJSON *kms_get_policy_request = cJSON_CreateObject();
    cJSON *kms_get_policy_response;
    cJSON_AddStringToObject(kms_get_policy_request, "KeyId", KMS_KEY_ID);

    if (!perform_kms_operation("Get key policy", kms_get_policy_request, "TrentService.GetKeyPolicy", &kms_get_policy_response)) {
        DEBUG_ERROR("KMS Get Policy operation failed\n");
        return 1;
    }

    cJSON_Delete(kms_get_policy_request);
    cJSON_Delete(kms_get_policy_response);
    // ************* END POLICY READ ************* //

    // ************* BEGIN ENCRYPTION ************* // 
    cJSON *kms_encrypt_request = cJSON_CreateObject();
    cJSON *kms_encrypt_response;
    cJSON_AddStringToObject(kms_encrypt_request, "KeyId", KMS_KEY_ID);
    cJSON_AddStringToObject(kms_encrypt_request, "EncryptionAlgorithm", "SYMMETRIC_DEFAULT");
    char plaintext_base64_encoded[sizeof(random_plaintext)*2]; /* should be enough for base64 encoding of random_plaintext */
    size_t plaintext_base64_encoded_len;
    mbedtls_base64_encode((unsigned char *)plaintext_base64_encoded, sizeof(plaintext_base64_encoded), &plaintext_base64_encoded_len, (unsigned char *)random_plaintext, strlen(random_plaintext));
    cJSON_AddStringToObject(kms_encrypt_request, "Plaintext", plaintext_base64_encoded);

    if (!perform_kms_operation("Encrypt", kms_encrypt_request, "TrentService.Encrypt", &kms_encrypt_response)) {
        DEBUG_ERROR("KMS Encrypt operation failed\n");
        return 1;
    }

    char* ciphertext;
    cJSON *ct_item = cJSON_GetObjectItemCaseSensitive(kms_encrypt_response, "CiphertextBlob");
    if (!cJSON_IsString(ct_item)) {
        DEBUG_ERROR("Missing CiphertextBlob in KMS Encrypt response JSON\n");
        return 1;
    }
    ciphertext = strdup(ct_item->valuestring);
    DEBUG("\n=== Ciphertext ===\n%s\n", ciphertext);

    cJSON_Delete(kms_encrypt_request);
    cJSON_Delete(kms_encrypt_response);
    // ************* END ENCRYPTION ************* // 

    // ************* BEGIN DECRYPTION ************* // 
    cJSON *kms_decrypt_request = cJSON_CreateObject();
    cJSON *kms_decrypt_response;
    cJSON_AddStringToObject(kms_decrypt_request, "KeyId", KMS_KEY_ID);
    cJSON_AddStringToObject(kms_decrypt_request, "CiphertextBlob", ciphertext);

    if (!perform_kms_operation("Decrypt", kms_decrypt_request, "TrentService.Decrypt", &kms_decrypt_response)) {
        DEBUG_ERROR("KMS Decrypt operation failed\n");
        return 1;
    }

#ifdef USE_TCP
    cJSON *pt_item = cJSON_GetObjectItemCaseSensitive(kms_decrypt_response, "Plaintext");
    if (!cJSON_IsString(pt_item)) {
        DEBUG_ERROR("Missing Plaintext in KMS response JSON\n");
        return 1;
    }
    char *plaintext_base64 = strdup(pt_item->valuestring);
    size_t plaintext_len = 4096;
    char *plaintext = malloc(plaintext_len); /* should be enough for decrypted plaintext */
    if (mbedtls_base64_decode(plaintext, plaintext_len, &plaintext_len, plaintext_base64, strlen(plaintext_base64))) {
        DEBUG_ERROR("Plaintext base64 decoding failed\n");
        return 1;
    }
    free(plaintext_base64);
#else
    cJSON *ctfr_item = cJSON_GetObjectItemCaseSensitive(kms_decrypt_response, "CiphertextForRecipient");
    if (!cJSON_IsString(ctfr_item)) {
        DEBUG_ERROR("Missing CiphertextForRecipient in KMS response JSON\n");
        return 1;
    }
    char *ct = strdup(ctfr_item->valuestring);

    uint8_t *plaintext;
    size_t plaintext_len;
    int decrypt_res;
    if (decrypt_res = decrypt_kms_ct_for_recipient(ct, strlen(ct), pri_der_start, pri_der_len, &plaintext, &plaintext_len)) {
        DEBUG_ERROR("Decrypt error: 0x%x\n", -decrypt_res);
        return 1;
    }
    free(ct);
#endif

    DEBUG("\n=== Plaintext ===\n%s\n", plaintext);

    free(plaintext);
    cJSON_Delete(kms_decrypt_request);
    cJSON_Delete(kms_decrypt_response);
    // ************* END DECRYPTION ************* // 
#ifndef USE_TCP
    mbedtls_pk_free(&pk);
#endif
    mbedtls_ctr_drbg_free(&G_ctr_drbg);
    mbedtls_entropy_free(&G_entropy);
    free_credentials();

#ifndef USE_TCP
    fflush(file_output);
    fclose(file_output);
    close(fd_output);
#endif

    return 0;
}