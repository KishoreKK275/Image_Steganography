#include "../include/stego.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Silence unused parameter warning */
#define UNUSED(x) (void)(x)

/* ------------------------------------------------ */

static long file_size(FILE *f) {
    fseek(f, 0, SEEK_END);
    long s = ftell(f);
    fseek(f, 0, SEEK_SET);
    return s;
}

static uint32_t bmp_pixel_offset(const uint8_t *buf) {
    return *(const uint32_t *)(buf + 10);
}

/* ================= ENCODE ================= */
size_t encode_bmp_lsb(
    const char *in,
    const uint8_t *data,
    size_t len,
    const char *out,
    const char *key1,
    const char *extn
) {
    UNUSED(data); /* payload is already encrypted by caller */

    FILE *fi = fopen(in, "rb");
    FILE *fo = fopen(out, "wb");
    if (!fi || !fo) return 0;

    long size = file_size(fi);
    uint8_t *buf = malloc(size);
    if (!buf) return 0;

    fread(buf, 1, size, fi);
    fclose(fi);

    size_t pos = bmp_pixel_offset(buf);
    size_t p;

    // Rough bounds check: Estimate available LSB bits (file size - header) / 8 for bytes
    size_t available_bytes = (size - pos) / 8;
    size_t required_bytes = 1 + strlen(key1) + 1 + strlen(extn) + 4 + len;  // klen + key1 + elen + extn + len + payload
    if (required_bytes > available_bytes) {
        free(buf);
        fclose(fo);
        return 0;  // Fail if payload too large
    }

    /* --- KEY1 LENGTH --- */
    uint8_t klen = (uint8_t)strlen(key1);
    for (int b = 7; b >= 0; b--) {
        p = pos++;
        buf[p] = (buf[p] & 0xFE) | ((klen >> b) & 1);
    }

    /* --- KEY1 DATA --- */
    for (uint8_t i = 0; i < klen; i++) {
        for (int b = 7; b >= 0; b--) {
            p = pos++;
            buf[p] = (buf[p] & 0xFE) | ((key1[i] >> b) & 1);
        }
    }

    /* --- EXTENSION --- */
    uint8_t elen = (uint8_t)strlen(extn);
    for (int b = 7; b >= 0; b--) {
        p = pos++;
        buf[p] = (buf[p] & 0xFE) | ((elen >> b) & 1);
    }

    for (uint8_t i = 0; i < elen; i++) {
        for (int b = 7; b >= 0; b--) {
            p = pos++;
            buf[p] = (buf[p] & 0xFE) | ((extn[i] >> b) & 1);
        }
    }

    /* --- PAYLOAD LENGTH --- */
    uint32_t L = (uint32_t)len;
    for (int i = 31; i >= 0; i--) {
        p = pos++;
        buf[p] = (buf[p] & 0xFE) | ((L >> i) & 1);
    }

    /* --- PAYLOAD --- */
    for (size_t i = 0; i < len; i++) {
        for (int b = 7; b >= 0; b--) {
            p = pos++;
            buf[p] = (buf[p] & 0xFE) | ((data[i] >> b) & 1);
        }
    }

    fwrite(buf, 1, size, fo);
    fclose(fo);
    free(buf);

    return len;
}

/* ================= DECODE ================= */
size_t decode_bmp_lsb(
    const char *bmp,
    uint8_t *out,
    size_t max_len,
    char *key1_out,
    char *extn_out
) {
    FILE *f = fopen(bmp, "rb");
    if (!f) return 0;

    long size = file_size(f);
    uint8_t *buf = malloc(size);
    if (!buf) return 0;

    fread(buf, 1, size, f);
    fclose(f);

    size_t pos = bmp_pixel_offset(buf);

    /* --- KEY1 LENGTH --- */
    uint8_t klen = 0;
    for (int i = 0; i < 8; i++)
        klen = (klen << 1) | (buf[pos++] & 1);

    if (klen == 0 || klen > KEY1_LEN) {
        free(buf);
        return 0;
    }

    /* --- KEY1 DATA --- */
    for (uint8_t i = 0; i < klen; i++) {
        uint8_t c = 0;
        for (int b = 0; b < 8; b++)
            c = (c << 1) | (buf[pos++] & 1);
        key1_out[i] = c;
    }
    key1_out[klen] = '\0';

    /* --- EXTENSION --- */
    uint8_t elen = 0;
    for (int i = 0; i < 8; i++)
        elen = (elen << 1) | (buf[pos++] & 1);

    if (elen >= 16) {
        free(buf);
        return 0;
    }

    for (uint8_t i = 0; i < elen; i++) {
        uint8_t c = 0;
        for (int b = 0; b < 8; b++)
            c = (c << 1) | (buf[pos++] & 1);
        extn_out[i] = c;
    }
    extn_out[elen] = '\0';

    /* --- PAYLOAD LENGTH --- */
    uint32_t len = 0;
    for (int i = 0; i < 32; i++)
        len = (len << 1) | (buf[pos++] & 1);

    if (len > max_len) {
        free(buf);
        return 0;
    }

    /* --- PAYLOAD --- */
    for (uint32_t i = 0; i < len; i++) {
        uint8_t c = 0;
        for (int b = 0; b < 8; b++)
            c = (c << 1) | (buf[pos++] & 1);
        out[i] = c;
    }

    free(buf);
    return len;
}