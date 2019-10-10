/* Tests for SHA-512 from LibTomCrypt */
/* This file is in the public domain */

/* gcc -o test_sha512 -I./src tests/test_sha512.c tests/test.c src/sha512.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha512.h"
#include "test.h"

int main(int argc, char **argv)
{
    static const struct {
        const char *msg;
        uint8_t hash[64];
    } tests[] = {
        {"abc",
         {0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73,
          0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9,
          0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21,
          0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23,
          0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8,
          0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f}},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklm"
         "nopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         {0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7,
          0x28, 0x14, 0xfc, 0x14, 0x3f, 0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f,
          0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18, 0x50,
          0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde,
          0xc4, 0xb5, 0x43, 0x3a, 0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26,
          0x54, 0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09}},
    };

    size_t i;
    uint8_t tmp[64];
    sha512_context md;

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        sha512_init(&md);
        sha512_process(&md, (uint8_t *)tests[i].msg, strlen(tests[i].msg));
        sha512_done(&md, tmp);
        COMPARE_BUF(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash));
    }

    /* success */
    fprintf(stdout, "ok\n");
    return (0);
}
