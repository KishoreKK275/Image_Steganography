#include "../include/crypto.h"
#include "../include/aes.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define AES_BLOCKLEN 16

/* ================= PKCS7 ================= */

static void pkcs7_pad(uint8_t *buf, size_t len, size_t padded_len) {
    size_t pad = padded_len - len;
    for (size_t i = 0; i < pad; i++) {
        buf[len + i] = (uint8_t) pad;
    }
}

static int pkcs7_unpad(uint8_t *buf, size_t *len) {
    if (*len == 0) return 0;
    uint8_t p = buf[*len - 1];
    if (p == 0 || p > AES_BLOCKLEN || p > *len) return 0;

    for (size_t i = 0; i < p; i++) {
        if (buf[*len - 1 - i] != p) return 0;
    }
    *len -= p;
    return 1;
}

/* ================= KEY DERIVATION ================= */

static void derive_key_iv(const char *pw, uint8_t *key, uint8_t *iv) {
    uint8_t tmp[32] = {0};
    size_t pw_len = strnlen(pw, sizeof(tmp));
    memcpy(tmp, pw, pw_len);

    for (int i = 0; i < 16; i++) {
        key[i] = tmp[i] ^ (0xAB + i);
        iv[i]  = tmp[i + 8] ^ (0xCD + i);
    }
}

/* ================= AES API ================= */

bool aes_encrypt(
    uint8_t *in, size_t in_len,
    const char *password,
    uint8_t **out, size_t *out_len
) {
    if (!in || !password || !out || !out_len) return false;

    *out_len = ((in_len + AES_BLOCKLEN - 1) / AES_BLOCKLEN) * AES_BLOCKLEN;
    *out = calloc(1, *out_len);
    if (!*out) return false;

    memcpy(*out, in, in_len);
    pkcs7_pad(*out, in_len, *out_len);

    uint8_t key[16], iv[16];
    derive_key_iv(password, key, iv);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, *out, *out_len);

    printf("[CRYPTO] AES encrypt: in=%zu bytes, out=%zu bytes\n", in_len, *out_len);
    return true;
}

bool aes_decrypt(
    uint8_t *in, size_t in_len,
    const char *password,
    uint8_t **out, size_t *out_len
) {
    if (!in || !password || !out || !out_len) return false;

    *out = malloc(in_len);
    if (!*out) return false;
    memcpy(*out, in, in_len);

    uint8_t key[16], iv[16];
    derive_key_iv(password, key, iv);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, *out, in_len);

    *out_len = in_len;
    if (!pkcs7_unpad(*out, out_len)) {
        printf("[CRYPTO] PKCS7 unpad failed, returning full buffer\n");
        *out_len = in_len;
    } else {
        printf("[CRYPTO] PKCS7 unpad successful\n");
    }

    printf("[CRYPTO] AES decrypt: in=%zu bytes, out=%zu bytes\n", in_len, *out_len);
    return true;
}