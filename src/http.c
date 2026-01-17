
#include "../include/http.h"
#include "../include/stego.h"
#include "../include/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // For unlink

#define LOG(fmt, ...) fprintf(stderr,"[SERVER] " fmt "\n",##__VA_ARGS__)
#define MIN_BMP_SIZE 54

void handle_encode(struct mg_connection *c, struct mg_http_message *hm) {
    LOG("ENCODE request received");

    struct mg_http_part part;
    size_t ofs = 0;
    uint8_t *img = NULL, *plain = NULL, *cipher = NULL;
    size_t img_len = 0, plain_len = 0, cipher_len = 0;
    char key1[129] = {0}, password[64] = {0}, ext[16] = "txt";  // Default to "txt"
    char input_file[256] = "input.bmp";

    while ((ofs = mg_http_next_multipart(hm->body, ofs, &part)) > 0) {
        if (!mg_vcmp(&part.name, "image")) {
            img_len = part.body.len;
            img = malloc(img_len);
            memcpy(img, part.body.ptr, img_len);
            // Reject SVG files
            if (part.filename.len >= 4 && strncmp(part.filename.ptr + part.filename.len - 4, ".svg", 4) == 0) {
                LOG("SVG files are not supported");
                mg_http_reply(c, 400, "", "SVG files are not supported\n");
                goto cleanup;
            }
        } else if (!mg_vcmp(&part.name, "txtFile")) {
            plain_len = part.body.len;
            plain = malloc(plain_len);
            memcpy(plain, part.body.ptr, plain_len);
            // Extract extension from filename (manual loop instead of memrchr for portability)
            if (part.filename.len > 0) {
                const char *fname = part.filename.ptr;
                size_t fnlen = part.filename.len;
                const char *dot = NULL;
                for (size_t i = 0; i < fnlen; i++) {
                    if (fname[i] == '.') {
                        dot = &fname[i];
                    }
                }
                if (dot) {
                    size_t ext_len = fnlen - (dot - fname) - 1;
                    if (ext_len < 15) {
                        memcpy(ext, dot + 1, ext_len);
                        ext[ext_len] = '\0';
                    } else {
                        strcpy(ext, "bin");
                    }
                }
            }
        } else if (!mg_vcmp(&part.name, "key1")) {
            strncpy(key1, part.body.ptr, 128);
        } else if (!mg_vcmp(&part.name, "password")) {
            strncpy(password, part.body.ptr, 63);
        }
    }

    if (!img || !plain || strlen(key1) != 128 || !password[0]) {
        LOG("Invalid encode input");
        mg_http_reply(c, 400, "", "Invalid input\n");
        goto cleanup;
    }

    LOG("Image size: %zu bytes", img_len);
    LOG("Plain size: %zu bytes", plain_len);

    // Handle image conversion to BMP if needed
    if (img_len < 2 || img[0] != 'B' || img[1] != 'M') {
        LOG("Converting image to BMP");
        FILE *ft = fopen("temp_input", "wb");
        if (!ft) {
            LOG("Failed to write temp_input");
            mg_http_reply(c, 500, "", "Server error\n");
            goto cleanup;
        }
        fwrite(img, 1, img_len, ft);
        fclose(ft);
        
        // Use magick convert (no fallback to avoid deprecation warnings)
        if (system("magick convert temp_input temp.bmp") != 0) {
            LOG("Image conversion failed");
            mg_http_reply(c, 500, "", "Image conversion failed\n");
            goto cleanup;
        }
        strcpy(input_file, "temp.bmp");
    } else {
        FILE *f = fopen("input.bmp", "wb");
        if (!f) {
            LOG("Failed to write input.bmp");
            mg_http_reply(c, 500, "", "Server file error\n");
            goto cleanup;
        }
        fwrite(img, 1, img_len, f);
        fclose(f);
    }

    if (!aes_encrypt(plain, plain_len, password, &cipher, &cipher_len)) {
        LOG("AES encryption failed");
        mg_http_reply(c, 500, "", "Encryption failed\n");
        goto cleanup;
    }

    LOG("Cipher size: %zu bytes", cipher_len);

    if (!encode_bmp_lsb(input_file, cipher, cipher_len, "encoded.bmp", key1, ext)) {
        LOG("Encoding failed");
        mg_http_reply(c, 500, "", "Encode failed\n");
        goto cleanup;
    }

    FILE *f = fopen("encoded.bmp", "rb");
    if (!f) {
        LOG("Failed to open encoded.bmp for sending");
        mg_http_reply(c, 500, "", "Server file error\n");
        goto cleanup;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    uint8_t *out = malloc(sz);
    fread(out, 1, sz, f);
    fclose(f);

    LOG("Encoded BMP size: %ld bytes", sz);
    mg_printf(c,
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: image/bmp\r\n"
              "Content-Length: %ld\r\n\r\n", sz);
    mg_send(c, out, sz);
    LOG("Sent %ld bytes to client", sz);

    free(out);

cleanup:
    if (img) free(img);
    if (plain) free(plain);
    if (cipher) free(cipher);
    unlink("temp_input");
    unlink("temp.bmp");
}

void handle_encode_decode(struct mg_connection *c, struct mg_http_message *hm) {
    // Combined encode + decode in one request for instant verification/download
    LOG("ENCODE-DECODE request received");

    struct mg_http_part part;
    size_t ofs = 0;
    uint8_t *img = NULL, *plain = NULL, *cipher = NULL, *decoded_plain = NULL;
    size_t img_len = 0, plain_len = 0, cipher_len = 0, decoded_len = 0;
    char key1[129] = {0}, password[64] = {0}, ext[16] = "txt";  // Default to "txt"
    char input_file[256] = "input.bmp", decoded_key1[129] = {0}, decoded_ext[16] = {0};

    while ((ofs = mg_http_next_multipart(hm->body, ofs, &part)) > 0) {
        if (!mg_vcmp(&part.name, "image")) {
            img_len = part.body.len;
            img = malloc(img_len);
            memcpy(img, part.body.ptr, img_len);
            // Reject SVG files
            if (part.filename.len >= 4 && strncmp(part.filename.ptr + part.filename.len - 4, ".svg", 4) == 0) {
                mg_http_reply(c, 400, "", "SVG files are not supported\n");
                goto cleanup;
            }
        } else if (!mg_vcmp(&part.name, "txtFile")) {
            plain_len = part.body.len;
            plain = malloc(plain_len);
            memcpy(plain, part.body.ptr, plain_len);
            // Extract extension from filename
            if (part.filename.len > 0) {
                const char *fname = part.filename.ptr;
                size_t fnlen = part.filename.len;
                const char *dot = NULL;
                for (size_t i = 0; i < fnlen; i++) {
                    if (fname[i] == '.') {
                        dot = &fname[i];
                    }
                }
                if (dot) {
                    size_t ext_len = fnlen - (dot - fname) - 1;
                    if (ext_len < 15) {
                        memcpy(ext, dot + 1, ext_len);
                        ext[ext_len] = '\0';
                    } else {
                        strcpy(ext, "bin");
                    }
                }
            }
        } else if (!mg_vcmp(&part.name, "key1")) {
            strncpy(key1, part.body.ptr, 128);
        } else if (!mg_vcmp(&part.name, "password")) {
            strncpy(password, part.body.ptr, 63);
        }
    }

    if (!img || !plain || strlen(key1) != 128 || !password[0]) {
        mg_http_reply(c, 400, "", "Invalid input\n");
        goto cleanup;
    }

    // Step 1: Encode (similar to handle_encode, but without sending BMP)
    if (img_len < 2 || img[0] != 'B' || img[1] != 'M') {
        FILE *ft = fopen("temp_input", "wb");
        if (!ft) {
            mg_http_reply(c, 500, "", "Server error\n");
            goto cleanup;
        }
        fwrite(img, 1, img_len, ft);
        fclose(ft);
        if (system("magick convert temp_input temp.bmp") != 0) {
            mg_http_reply(c, 500, "", "Image conversion failed\n");
            goto cleanup;
        }
        strcpy(input_file, "temp.bmp");
    } else {
        FILE *f = fopen("input.bmp", "wb");
        if (!f) {
            mg_http_reply(c, 500, "", "Server file error\n");
            goto cleanup;
        }
        fwrite(img, 1, img_len, f);
        fclose(f);
    }

    if (!aes_encrypt(plain, plain_len, password, &cipher, &cipher_len)) {
        mg_http_reply(c, 500, "", "Encryption failed\n");
        goto cleanup;
    }

    if (!encode_bmp_lsb(input_file, cipher, cipher_len, "encoded.bmp", key1, ext)) {
        mg_http_reply(c, 500, "", "Encode failed\n");
        goto cleanup;
    }

    // Step 2: Decode immediately (similar to handle_decode, but from the just-encoded BMP)
    FILE *f = fopen("encoded.bmp", "rb");
    if (!f) {
        mg_http_reply(c, 500, "", "Server error\n");
        goto cleanup;
    }
    fseek(f, 0, SEEK_END);
    size_t bmp_size = ftell(f);
    rewind(f);
    uint8_t *bmp_data = malloc(bmp_size);
    fread(bmp_data, 1, bmp_size, f);
    fclose(f);

    uint8_t *decoded_cipher = malloc(bmp_size);
    size_t decoded_cipher_len = decode_bmp_lsb("encoded.bmp", decoded_cipher, bmp_size, decoded_key1, decoded_ext);

    if (decoded_cipher_len == 0 || decoded_cipher_len > bmp_size || strcmp(key1, decoded_key1) != 0) {
        mg_http_reply(c, 400, "", "Verification failed\n");
        free(bmp_data);
        free(decoded_cipher);
        goto cleanup;
    }

    if (!aes_decrypt(decoded_cipher, decoded_cipher_len, password, &decoded_plain, &decoded_len)) {
        mg_http_reply(c, 500, "", "Decryption failed\n");
        free(bmp_data);
        free(decoded_cipher);
        goto cleanup;
    }

    // Send the decoded file directly
    mg_printf(c,
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: application/octet-stream\r\n"
              "Content-Length: %lu\r\n"
              "Content-Disposition: attachment; filename=\"verified.%s\"\r\n\r\n",
              (unsigned long)decoded_len, decoded_ext[0] ? decoded_ext : "txt");
    mg_send(c, decoded_plain, decoded_len);

    free(bmp_data);
    free(decoded_cipher);

cleanup:
    if (img) free(img);
    if (plain) free(plain);
    if (cipher) free(cipher);
    if (decoded_plain) free(decoded_plain);
    unlink("temp_input");
    unlink("temp.bmp");
    unlink("encoded.bmp");
}

void handle_decode(struct mg_connection *c, struct mg_http_message *hm) {
    LOG("DECODE request received");

    struct mg_http_part part;
    size_t ofs = 0;

    uint8_t *bmp = NULL, *cipher = NULL, *plain = NULL;
    size_t bmp_len = 0, cipher_len = 0, plain_len = 0;
    char key1[129] = {0}, password[64] = {0}, ext[16] = {0}, decoded_key1[129] = {0};

    while ((ofs = mg_http_next_multipart(hm->body, ofs, &part)) > 0) {
        if (!mg_vcmp(&part.name, "bmp")) {
            bmp_len = part.body.len;
            if (bmp_len > 0) {
                bmp = malloc(bmp_len);
                memcpy(bmp, part.body.ptr, bmp_len);
            }
        } else if (!mg_vcmp(&part.name, "key1")) {
            strncpy(key1, part.body.ptr, 128);
        } else if (!mg_vcmp(&part.name, "password")) {
            strncpy(password, part.body.ptr, 63);
        }
    }

    // VALIDATION
    if (!bmp || bmp_len < MIN_BMP_SIZE) {
        LOG("Decode aborted: missing or invalid BMP");
        mg_http_reply(c, 400, "", "Encoded BMP required\n");
        goto cleanup;
    }

    if (strlen(key1) != 128) {
        LOG("Decode aborted: invalid key1");
        mg_http_reply(c, 400, "", "Invalid key1\n");
        goto cleanup;
    }

    if (!password[0]) {
        LOG("Decode aborted: missing password");
        mg_http_reply(c, 400, "", "Password required\n");
        goto cleanup;
    }

    LOG("BMP size: %zu bytes", bmp_len);

    FILE *f = fopen("encoded.bmp", "wb");
    if (!f) {
        LOG("Failed to open encoded.bmp for writing");
        mg_http_reply(c, 500, "", "Server error\n");
        goto cleanup;
    }
    fwrite(bmp, 1, bmp_len, f);
    fclose(f);

    cipher = malloc(bmp_len);
    cipher_len = decode_bmp_lsb("encoded.bmp", cipher, bmp_len, decoded_key1, ext);

    if (cipher_len == 0 || cipher_len > bmp_len) {
        LOG("Decode failed: corrupted or invalid data");
        mg_http_reply(c, 400, "", "Decode failed\n");
        goto cleanup;
    }

    // Verify Key1
    if (strcmp(key1, decoded_key1) != 0) {
        LOG("Key1 mismatch");
        mg_http_reply(c, 400, "", "Invalid key1\n");
        goto cleanup;
    }

    if (!aes_decrypt(cipher, cipher_len, password, &plain, &plain_len)) {
        LOG("AES decrypt failed");
        mg_http_reply(c, 500, "", "Decryption failed\n");
        goto cleanup;
    }

    LOG("Decoded plain size: %zu bytes", plain_len);

   mg_printf(c,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %lu\r\n"
        "Content-Disposition: attachment; filename=\"decoded.%s\"\r\n\r\n",
        (unsigned long)plain_len, ext[0] ? ext : "txt");

    mg_send(c, plain, plain_len);

cleanup:
    if (bmp) free(bmp);
    if (cipher) free(cipher);
    if (plain) free(plain);
}