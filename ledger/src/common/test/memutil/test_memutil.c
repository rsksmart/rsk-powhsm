#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#include "memutil.h"

void os_memmove(void *dst, const void *src, unsigned int length) {
}

void test_ok() {
    printf("Test OK...\n");
    char src[15];
    char dst[10];

    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), 10, { assert(false); });
    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), 9, { assert(false); });
    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), 4, { assert(false); });
}

void test_negative() {
    printf("Test negative length...\n");
    char src[15];
    char dst[10];

    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), -1, { return; });
    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), -5, { return; });
    assert(false);
}

void test_src_outofbounds() {
    printf("Test read src out of bounds...\n");
    char src[5];
    char dst[10];

    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), 6, { return; });
    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), 7, { return; });
    assert(false);
}

void test_dst_outofbounds() {
    printf("Test read dst out of bounds...\n");
    char src[15];
    char dst[10];

    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), 11, { return; });
    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), 13, { return; });
    assert(false);
}

int main() {
    test_ok();
    test_negative();
    test_src_outofbounds();
    test_dst_outofbounds();
    return 0;
}