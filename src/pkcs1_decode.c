/* ===================================================================
 *
 * Copyright (c) 2021, Helder Eijs <helderijs@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ===================================================================
 */

#include "common.h"

FAKE_INIT(pkcs1_decode)

/*
 * Return 0 if x is 0, otherwise 0xFF
 */
STATIC uint8_t propagate_ones(uint8_t x)
{
    unsigned i;
    uint8_t result;

    result = x;
    for (i=0; i<8; i++) {
        x = (x << 1) | (x >> 7);
        result |= x;
    }

    return result;
}

/*
 * Return 0 if x is 0, otherwise (size_t)-1
 */
STATIC size_t propagate_ones_long(uint8_t x)
{
    size_t result;
    uint8_t inter;
    unsigned i;

    inter = propagate_ones(x);
    result = 0;
    for (i=0; i<sizeof(result); i++) {
        result |= ((size_t)inter) << (i*8);
    }
    return result;
}

/*
 * Copy in1[] into out[] if choice is 0, otherwise copy in2[]
 */
STATIC void safe_select(const uint8_t *in1, const uint8_t *in2, uint8_t *out, uint8_t choice, size_t len)
{
    size_t i;
    uint8_t mask1, mask2;

    mask1 = propagate_ones(choice);
    mask2 = ~mask1;
    for (i=0; i<len; i++) {
        out[i] = (in1[i] & mask2) | (in2[i] & mask1);
        mask1 = (mask1 << 1) | (mask1 >> 7);
        mask2 = (mask2 << 1) | (mask2 >> 7);
    }
}

#define LEN_SIZE_T (sizeof(size_t))

STATIC size_t safe_select_idx(size_t in1, size_t in2, uint8_t choice)
{
    uint8_t in1b[LEN_SIZE_T];
    uint8_t in2b[LEN_SIZE_T];
    uint8_t resb[LEN_SIZE_T];
    size_t result;
    unsigned i;

    /** Little endian **/
    for (i=0; i<LEN_SIZE_T; i++) {
        in1b[i] = (uint8_t)(in1 >> (i*8));
        in2b[i] = (uint8_t)(in2 >> (i*8));
    }

    safe_select(in1b, in2b, resb, choice, LEN_SIZE_T);

    result = 0;
    for (i=0; i<LEN_SIZE_T; i++) {
        result |= (size_t)resb[i] << (i*8);
    }

    return result;
}

/*
 * Return 0 if in1[] is equal to in2[] when eq_mask[] is 0xFF,
 * and if in1[] is different than in2[] when neq_mask[] is 0xFF.
 * Return non-zero otherwise.
 */
STATIC uint8_t safe_cmp(const uint8_t *in1, const uint8_t *in2,
                 const uint8_t *eq_mask, const uint8_t *neq_mask,
                 size_t len)
{
    size_t i;
    uint8_t c, result;

    result = 0;
    for (i=0; i<len; i++) {
        c = propagate_ones(*in1++ ^ *in2++);
        result |= c & *eq_mask++;
        result |= ~c & *neq_mask++;
    }

    return result;
}

/*
 * Return the index of the byte with value c,
 * or the length of in1[] when c is not present
 */
STATIC size_t safe_search(const uint8_t *in1, uint8_t c, size_t len)
{
    size_t result, mask1, mask2, i;
    uint8_t *in2;

    in2 = (uint8_t*) malloc(len + 1);
    memcpy(in2, in1, len);
    in2[len] = c;

    result = 0;
    mask2 = 0;
    for (i=0; i<(len+1); i++) {
        mask1 = ~mask2 & ~propagate_ones_long(in2[i] ^ c);
        result |= i & mask1;
        mask2 |= mask1;
    }

    free(in2);
    return result;
}

/*
 * Decode and verify the PKCS#1 padding, then put either the plaintext
 * or the sentinel value into the output buffer in constant time.
 *
 * The output is a buffer of equal length as the encoded message (em).
 *
 * The sentinel is put into the buffer when decryption fails.
 *
 * The function returns the number of bytes to ignore at the beginning
 * of the output buffer.
 */
EXPORT_SYM int pkcs1_decode(const uint8_t *em, size_t len_em,
                            const uint8_t *sentinel, size_t len_sentinel,
                            uint8_t *output)
{
    size_t pos;
    uint8_t match, x, selector;
    uint8_t *padded_sentinel;
    unsigned i;

    if (NULL == em || NULL == output || NULL == sentinel) {
        return -1;
    }
    if (len_em < 10) {
        return -1;
    }
    if (len_sentinel > len_em) {
        return -1;
    }

    padded_sentinel = (uint8_t*) calloc(1, len_em);
    if (NULL == padded_sentinel) {
        return -1;
    }
    memcpy(padded_sentinel + (len_em - len_sentinel), sentinel, len_sentinel);

    /** The first 10 bytes must follow the pattern **/
    match = safe_cmp(em,
                     (const uint8_t*)"\x00\x02" "\x00\x00\x00\x00\x00\x00\x00\x00",
                     (const uint8_t*)"\xFF\xFF" "\x00\x00\x00\x00\x00\x00\x00\x00",
                     (const uint8_t*)"\x00\x00" "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                     10);

    /*
     * pos is the index of the first 0 byte.
     * It can be (len_em-1) when the 0 is at the end (empty M).
     * It can be len_em when the 0 is not present (error).
     */
    pos = safe_search(em + 10, 0, len_em - 10) + 10;

    /* selector is 0 if there is a match for the first 10 bytes AND
     * if a 0 byte is found in the remainder of em
     */
    selector = match;
    x = 0;
    for (i=0; i<sizeof len_em; i++) {
        x |= (uint8_t)((pos ^ len_em) >> (i*8));
    }
    selector = match | ~propagate_ones(x);

    /** Select the correct data to output **/
    safe_select(em, padded_sentinel, output, selector, len_em);
    free(padded_sentinel);

    /** Select the number of bytes that the caller will skip in output **/
    return (int)safe_select_idx(pos + 1, len_em - len_sentinel, selector);
}
