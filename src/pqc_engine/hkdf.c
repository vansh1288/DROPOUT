#include "hkdf.h"
#include <tinycrypt/hmac.h>
#include <string.h>

int hkdf_sha256_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t* prk) {
    if (!ikm || !prk) return -1;
    if (!salt && salt_len > 0) return -1;

    struct tc_hmac_state_struct hmac;
    if (salt && salt_len) {
        tc_hmac_set_key(&hmac, salt, salt_len);
    } else {
        uint8_t zero_salt[32] = {0};
        tc_hmac_set_key(&hmac, zero_salt, 32);
    }
    tc_hmac_init(&hmac);
    tc_hmac_update(&hmac, ikm, ikm_len);
    tc_hmac_final(prk, 32, &hmac);
    return 0;
}

int hkdf_sha256_expand(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) {
    if (!prk || !okm) return -1;
    if (!info && info_len > 0) return -1;
    if (prk_len != 32) return -1;
    if (okm_len > HKDF_SHA256_MAX_OUTPUT_LEN) return -1;

    struct tc_hmac_state_struct hmac;
    uint8_t t[32];
    size_t t_len = 0;
    uint8_t ctr = 1;
    uint8_t* out = okm;
    size_t remaining = okm_len;

    tc_hmac_set_key(&hmac, prk, prk_len);

    while (remaining > 0) {
        tc_hmac_init(&hmac);
        if (t_len) {
            tc_hmac_update(&hmac, t, t_len);
        }
        if (info && info_len) {
            tc_hmac_update(&hmac, info, info_len);
        }
        tc_hmac_update(&hmac, &ctr, 1);
        tc_hmac_final(t, 32, &hmac);
        t_len = 32;

        size_t chunk = remaining < 32 ? remaining : 32;
        for (size_t i = 0; i < chunk; i++) {
            out[i] = t[i];
        }
        out += chunk;
        remaining -= chunk;
        ctr++;
    }
    return 0;
}

int hkdf_sha256(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) {
    uint8_t prk[32];
    int ret = hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk);
    if (ret != 0) return ret;
    ret = hkdf_sha256_expand(prk, 32, info, info_len, okm, okm_len);
    return ret;
}