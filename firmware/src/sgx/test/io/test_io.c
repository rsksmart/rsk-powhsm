/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2021 RSK Labs Ltd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "io.h"

#define TEST_PORT 12345
#define TEST_HOST "127.0.0.1"

#define DO_IO_INIT()                             \
    {                                            \
        if (!io_init(TEST_PORT, TEST_HOST)) {    \
            fprintf(stderr, "io_init failed\n"); \
            assert(false);                       \
        }                                        \
    }

#define DO_CREATE_CLIENT(client_fn)                                  \
    pthread_t __client__;                                            \
    if (pthread_create(&__client__, NULL, (client_fn), NULL) != 0) { \
        perror("Failed to create client thread");                    \
        io_finalise();                                               \
        assert(false);                                               \
    }

#define DO_FINALISE()               \
    pthread_join(__client__, NULL); \
    io_finalise();

#define ASSERT_IO_EXCHANGE_RECV(payload, len)                       \
    {                                                               \
        unsigned short __rx__ = io_exchange(0);                     \
                                                                    \
        if (__rx__ != (len)) {                                      \
            fprintf(stderr,                                         \
                    "FAIL: request mismatch -- "                    \
                    "expected %lu bytes, got %u\n",                 \
                    (len),                                          \
                    __rx__);                                        \
            assert(false);                                          \
        }                                                           \
                                                                    \
        if (memcmp(io_apdu_buffer, (payload), (len)) != 0) {        \
            fprintf(stderr, "FAIL: request mismatch -- payload\n"); \
            assert(false);                                          \
        }                                                           \
    }

#define ASSERT_IO_EXCHANGE_RECV_BLANK_LEN(len)                              \
    {                                                                       \
        unsigned short __rx__ = io_exchange(0);                             \
                                                                            \
        if (__rx__ != (len)) {                                              \
            fprintf(stderr,                                                 \
                    "FAIL: blank request mismatch -- "                      \
                    "expected %lu bytes, got %u\n",                         \
                    (len),                                                  \
                    __rx__);                                                \
            assert(false);                                                  \
        }                                                                   \
                                                                            \
        for (unsigned __i__ = 0; __i__ < sizeof(io_apdu_buffer); __i__++) { \
            if (io_apdu_buffer[__i__] != 0) {                               \
                fprintf(stderr,                                             \
                        "FAIL: blank request "                              \
                        "mismatch -- payload\n");                           \
                assert(false);                                              \
            }                                                               \
        }                                                                   \
    }

#define ASSERT_SEND_RESPONSE(payload, len)                               \
    {                                                                    \
        io_apdu_buffer[0] = 0x80;                                        \
        memcpy(io_apdu_buffer + 1, (payload), (len));                    \
        io_apdu_buffer[(len) + 1] = 0x91;                                \
        io_apdu_buffer[(len) + 2] = 0x92;                                \
        unsigned short __rx__ = io_exchange((len) + 3);                  \
        if (__rx__ != 0) {                                               \
            fprintf(stderr,                                              \
                    "FAIL: expected a zero-length reply from client\n"); \
            assert(false);                                               \
        }                                                                \
    }

#define CLIENT_ASSERT_CONNECT_NOVAR()                    \
    __sockfd__ = socket(AF_INET, SOCK_STREAM, 0);        \
    if (__sockfd__ < 0) {                                \
        perror("Client socket creation failed");         \
        assert(false);                                   \
    }                                                    \
                                                         \
    memset(&__servaddr__, 0, sizeof(__servaddr__));      \
    __servaddr__.sin_family = AF_INET;                   \
    __servaddr__.sin_port = htons(TEST_PORT);            \
    __servaddr__.sin_addr.s_addr = inet_addr(TEST_HOST); \
                                                         \
    if (connect(__sockfd__,                              \
                (struct sockaddr *)&__servaddr__,        \
                sizeof(__servaddr__)) < 0) {             \
        perror("Client connect failed");                 \
        close(__sockfd__);                               \
        assert(false);                                   \
    }

#define CLIENT_ASSERT_CONNECT()      \
    int __sockfd__;                  \
    struct sockaddr_in __servaddr__; \
    CLIENT_ASSERT_CONNECT_NOVAR();

#define CLIENT_SEND_LENGTH(len)                                 \
    {                                                           \
        uint32_t __net_len__ = htonl((len));                    \
        send(__sockfd__, &__net_len__, sizeof(__net_len__), 0); \
    }

#define CLIENT_SEND_BYTES(payload, len) send(__sockfd__, (payload), (len), 0);

#define CLIENT_SEND(payload, len) \
    CLIENT_SEND_LENGTH(len);      \
    if ((len) > 0)                \
        CLIENT_SEND_BYTES(payload, len);

#define CLIENT_WAIT_FOR_SERVER() usleep(100 * 1000);

#define CLIENT_RECV_ASSERT_RESPONSE(payload, len)                            \
    {                                                                        \
        unsigned char __buffer__[APDU_BUFFER_SIZE];                          \
        uint32_t __len__;                                                    \
        CLIENT_WAIT_FOR_SERVER();                                            \
        size_t __n__ = recv(__sockfd__, __buffer__, sizeof(__buffer__), 0);  \
                                                                             \
        if (__n__ < sizeof(__len__)) {                                       \
            printf("Client receive failed: expected at least %lu bytes but " \
                   "got %lu bytes\n",                                        \
                   sizeof(__len__),                                          \
                   __n__);                                                   \
            close(__sockfd__);                                               \
            assert(false);                                                   \
        }                                                                    \
                                                                             \
        memcpy(&__len__, __buffer__, sizeof(__len__));                       \
        __len__ = ntohl(__len__);                                            \
                                                                             \
        if (__n__ != __len__ + sizeof(__len__) + 2) {                        \
            fprintf(stderr,                                                  \
                    "FAIL: response size mismatch -- "                       \
                    "expected %lu bytes, got %lu\n",                         \
                    __len__ + sizeof(__len__),                               \
                    __n__);                                                  \
            assert(false);                                                   \
        }                                                                    \
                                                                             \
        if (__len__ != (len) + 1) {                                          \
            fprintf(stderr,                                                  \
                    "FAIL: response mismatch -- "                            \
                    "expected %lu bytes, got %lu\n",                         \
                    (len),                                                   \
                    __n__);                                                  \
            assert(false);                                                   \
        }                                                                    \
        unsigned char *__apdu__ = __buffer__ + sizeof(__len__);              \
                                                                             \
        if (__apdu__[0] != 0x80) {                                           \
            fprintf(stderr, "FAIL: response CLA mismatch\n");                \
            assert(false);                                                   \
        }                                                                    \
        if (__apdu__[(len) + 1] != 0x91 || __apdu__[(len) + 2] != 0x92) {    \
            fprintf(stderr, "FAIL: response SW mismatch\n");                 \
            assert(false);                                                   \
        }                                                                    \
        if (memcmp(__apdu__ + 1, (payload), (len)) != 0) {                   \
            fprintf(stderr, "FAIL: response mismatch -- payload\n");         \
            assert(false);                                                   \
        }                                                                    \
    }

#define CLIENT_CLOSE_NOEXIT() close(__sockfd__);

#define CLIENT_CLOSE() \
    close(__sockfd__); \
    pthread_exit(NULL);

#define CLIENT_REPLY_AND_CLOSE()                      \
    uint32_t __zero__ = 0;                            \
    send(__sockfd__, &__zero__, sizeof(__zero__), 0); \
    CLIENT_CLOSE();

// Client for request/response test cases
struct {
    const uint8_t *req_payload;
    size_t req_len;
    const uint8_t *expected_res_payload;
    size_t expected_res_len;
} G_clrr_config;

void *client_request_response() {
    CLIENT_ASSERT_CONNECT();
    CLIENT_SEND(G_clrr_config.req_payload, G_clrr_config.req_len);

    CLIENT_RECV_ASSERT_RESPONSE(G_clrr_config.expected_res_payload,
                                G_clrr_config.expected_res_len);

    CLIENT_REPLY_AND_CLOSE();
}

void test_request_response_ok(const char *test_name,
                              const char *req_payload,
                              size_t req_len,
                              const char *res_payload,
                              size_t res_len) {
    printf("Testing request/response %s...\n", test_name);

    // Configure client behavior
    G_clrr_config.req_payload = (uint8_t *)req_payload;
    G_clrr_config.req_len = req_len;
    G_clrr_config.expected_res_payload = (uint8_t *)res_payload;
    G_clrr_config.expected_res_len = res_len;

    DO_IO_INIT();
    DO_CREATE_CLIENT(client_request_response);
    ASSERT_IO_EXCHANGE_RECV(req_payload, req_len);
    ASSERT_SEND_RESPONSE(res_payload, res_len);
    DO_FINALISE();

    printf("OK\n");
}

const char MOCK_REQUEST[] = "a-request";
const char MOCK_RESPONSE[] = "a-response";

char G_client_pause_during_send_config;

void *client_pause_during_send() {
    CLIENT_ASSERT_CONNECT();

    if (G_client_pause_during_send_config == 'l' ||
        G_client_pause_during_send_config == 'a') {
        CLIENT_SEND_BYTES("\x00\x00", 2);
        usleep(200 * 1000);
        CLIENT_SEND_BYTES("\x00\x09", 2);
    } else {
        CLIENT_SEND_LENGTH(strlen(MOCK_REQUEST));
    }
    if (G_client_pause_during_send_config == 'b' ||
        G_client_pause_during_send_config == 'a')
        usleep(200 * 1000);
    CLIENT_SEND_BYTES(MOCK_REQUEST, 5);
    if (G_client_pause_during_send_config == 'p' ||
        G_client_pause_during_send_config == 'a')
        usleep(200 * 1000);
    CLIENT_SEND_BYTES(MOCK_REQUEST + 5, strlen(MOCK_REQUEST) - 5);

    CLIENT_RECV_ASSERT_RESPONSE(MOCK_RESPONSE, strlen(MOCK_RESPONSE));
    CLIENT_REPLY_AND_CLOSE();
}

void test_pause_during_send(char client_config) {
    printf("Testing client pausing during send (mode %c)...\n", client_config);

    DO_IO_INIT();
    G_client_pause_during_send_config = client_config;
    DO_CREATE_CLIENT(client_pause_during_send);
    ASSERT_IO_EXCHANGE_RECV(MOCK_REQUEST, strlen(MOCK_REQUEST));
    ASSERT_SEND_RESPONSE(MOCK_RESPONSE, strlen(MOCK_RESPONSE));
    DO_FINALISE();

    printf("OK\n");
}

void *client_apdu_length_too_big() {
    uint8_t mock_payload[3000];
    memset(mock_payload, 0xAA, sizeof(mock_payload));

    CLIENT_ASSERT_CONNECT();
    CLIENT_SEND(mock_payload, sizeof(mock_payload));
    CLIENT_WAIT_FOR_SERVER();
    CLIENT_RECV_ASSERT_RESPONSE(MOCK_RESPONSE, strlen(MOCK_RESPONSE));
    CLIENT_REPLY_AND_CLOSE();
}

void test_apdu_length_too_big() {
    printf("Testing client sending APDU length that's too big...\n");

    DO_IO_INIT();
    DO_CREATE_CLIENT(client_apdu_length_too_big);
    ASSERT_IO_EXCHANGE_RECV_BLANK_LEN(3000LU);
    ASSERT_SEND_RESPONSE(MOCK_RESPONSE, strlen(MOCK_RESPONSE));
    DO_FINALISE();

    printf("OK\n");
}

void *client_request_plus_more() {
    CLIENT_ASSERT_CONNECT();
    CLIENT_SEND_BYTES("\x00\x00\x00\x04"
                      "abcd"
                      "thisisalotofextrarubbish",
                      4 + strlen("abcd") + strlen("thisisalotofextrarubbish"));
    CLIENT_CLOSE();
}

void test_request_plus_more() {
    printf("Testing client sending extra bytes...\n");

    DO_IO_INIT();
    DO_CREATE_CLIENT(client_request_plus_more);
    ASSERT_IO_EXCHANGE_RECV("abcd", strlen("abcd"));
    DO_FINALISE();

    printf("OK\n");
}

void *client_two_requests_at_once() {
    CLIENT_ASSERT_CONNECT();
    CLIENT_SEND_BYTES("\x00\x00\x00\x04"
                      "abcd"
                      "\x00\x00\x00\x05"
                      "efghi",
                      4 + strlen("abcd") + 4 + strlen("efghi"));
    CLIENT_CLOSE();
}

void test_two_requests_at_once() {
    printf("Testing client sending two requests at once...\n");

    DO_IO_INIT();
    DO_CREATE_CLIENT(client_two_requests_at_once);
    ASSERT_IO_EXCHANGE_RECV("abcd", strlen("abcd"));
    ASSERT_IO_EXCHANGE_RECV("efghi", strlen("efghi"));
    DO_FINALISE();

    printf("OK\n");
}

void *client_hgup_during_length() {
    CLIENT_ASSERT_CONNECT();
    CLIENT_SEND_BYTES("\xab\xcd\xef", 3);
    CLIENT_CLOSE_NOEXIT();

    CLIENT_ASSERT_CONNECT_NOVAR();
    CLIENT_SEND(MOCK_REQUEST, strlen(MOCK_REQUEST));
    CLIENT_RECV_ASSERT_RESPONSE(MOCK_RESPONSE, strlen(MOCK_RESPONSE));
    CLIENT_REPLY_AND_CLOSE();
}

void test_hgup_during_length() {
    printf("Testing client hanging up during length...\n");

    DO_IO_INIT();
    DO_CREATE_CLIENT(client_hgup_during_length);
    ASSERT_IO_EXCHANGE_RECV(MOCK_REQUEST, strlen(MOCK_REQUEST));
    ASSERT_SEND_RESPONSE(MOCK_RESPONSE, strlen(MOCK_RESPONSE));
    DO_FINALISE();

    printf("OK\n");
}

void *client_hgup_during_payload() {
    CLIENT_ASSERT_CONNECT();
    CLIENT_SEND_LENGTH(100);
    CLIENT_SEND_BYTES("hello", strlen("hello"));
    CLIENT_CLOSE_NOEXIT();

    CLIENT_ASSERT_CONNECT_NOVAR();
    CLIENT_SEND(MOCK_REQUEST, strlen(MOCK_REQUEST));
    CLIENT_RECV_ASSERT_RESPONSE(MOCK_RESPONSE, strlen(MOCK_RESPONSE));
    CLIENT_REPLY_AND_CLOSE();
}

void test_hgup_during_payload() {
    printf("Testing client hanging up during payload...\n");

    DO_IO_INIT();
    DO_CREATE_CLIENT(client_hgup_during_payload);
    ASSERT_IO_EXCHANGE_RECV(MOCK_REQUEST, strlen(MOCK_REQUEST));
    ASSERT_SEND_RESPONSE(MOCK_RESPONSE, strlen(MOCK_RESPONSE));
    DO_FINALISE();

    printf("OK\n");
}

int main() {
    test_request_response_ok("hello, goodbye", "Hello", 5, "Goodbye", 7);
    test_request_response_ok("empty, empty", "", 0, "", 0);
    test_request_response_ok("foo, empty", "foo", 3, "", 0);
    test_request_response_ok(
        "empty, gimmesomething", "", 0, "gimmesomething", 14);

    test_pause_during_send('l');
    test_pause_during_send('b');
    test_pause_during_send('p');
    test_pause_during_send('a');

    test_request_plus_more();
    test_two_requests_at_once();

    test_apdu_length_too_big();
    test_hgup_during_length();
    test_hgup_during_payload();

    return 0;
}
