#include "dragonfly_sim.h"

#include <string.h>
#include <stdint.h>
#include <stdatomic.h>

#include "esp_log.h"

static atomic_bool s_init = ATOMIC_VAR_INIT(false);
static const char *TAG = "dragonfly";

/* ==========================================================================
 *  Self-contained FIPS 180-4 SHA-256, HMAC-SHA256 & PBKDF2-HMAC-SHA256
 *  (Compatible with ESP-IDF v5.x and v6.x / Mbed TLS 3.x & 4.0)
 * ========================================================================== */

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t buffer[64];
} sha256_ctx_t;

static const uint32_t K256[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static inline uint32_t rotr32(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32U - n));
}

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i * 4 + 0] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8)  |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx)
{
    ctx->state[0] = 0x6a09e667UL; ctx->state[1] = 0xbb67ae85UL;
    ctx->state[2] = 0x3c6ef372UL; ctx->state[3] = 0xa54ff53aUL;
    ctx->state[4] = 0x510e527fUL; ctx->state[5] = 0x9b05688cUL;
    ctx->state[6] = 0x1f83d9abUL; ctx->state[7] = 0x5be0cd19UL;
    ctx->bitcount = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (len == 0) return;
    size_t idx = (size_t)((ctx->bitcount >> 3) & 0x3FU);
    ctx->bitcount += (uint64_t)len << 3;

    size_t part_len = 64U - idx;
    size_t i = 0;
    if (len >= part_len) {
        memcpy(&ctx->buffer[idx], data, part_len);
        sha256_transform(ctx, ctx->buffer);
        for (i = part_len; i + 63U < len; i += 64U) {
            sha256_transform(ctx, &data[i]);
        }
        idx = 0;
    }
    memcpy(&ctx->buffer[idx], &data[i], len - i);
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t digest[32])
{
    uint8_t bits[8];
    for (int i = 0; i < 8; i++) {
        bits[i] = (uint8_t)(ctx->bitcount >> ((7 - i) * 8));
    }
    size_t idx = (size_t)((ctx->bitcount >> 3) & 0x3FU);
    size_t pad_len = (idx < 56U) ? (56U - idx) : (120U - idx);
    uint8_t pad[64];
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80U;
    sha256_update(ctx, pad, pad_len);
    sha256_update(ctx, bits, 8);
    for (int i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[32])
{
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t tk[32];

    if (key_len > 64) {
        sha256_ctx_t tctx;
        sha256_init(&tctx);
        sha256_update(&tctx, key, key_len);
        sha256_final(&tctx, tk);
        key = tk;
        key_len = 32;
    }

    memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));
    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    sha256_ctx_t ctx;
    uint8_t inner[32];
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner);

    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, out);
}

static void pbkdf2_hmac_sha256(const uint8_t *password, size_t pwd_len,
                               const uint8_t *salt, size_t salt_len,
                               uint32_t iterations, uint8_t out[32])
{
    uint8_t u[32];
    uint8_t t[32];
    uint8_t salt_blk[128];
    if (salt_len > sizeof(salt_blk) - 4) {
        salt_len = sizeof(salt_blk) - 4;
    }
    memcpy(salt_blk, salt, salt_len);
    salt_blk[salt_len + 0] = 0;
    salt_blk[salt_len + 1] = 0;
    salt_blk[salt_len + 2] = 0;
    salt_blk[salt_len + 3] = 1;

    hmac_sha256(password, pwd_len, salt_blk, salt_len + 4, u);
    memcpy(t, u, 32);

    for (uint32_t i = 1; i < iterations; i++) {
        hmac_sha256(password, pwd_len, u, 32, u);
        for (int j = 0; j < 32; j++) {
            t[j] ^= u[j];
        }
    }
    memcpy(out, t, 32);
}

esp_err_t dragonfly_sim_init(void)
{
    atomic_store(&s_init, true);
    ESP_LOGI(TAG, "Dragonfly simulator initialized (PBKDF2-SHA256)");
    return ESP_OK;
}

bool dragonfly_sim_validate(const uint8_t *password, size_t pwd_len,
                            const uint8_t *pmk, 
                            const uint8_t *salt, size_t salt_len)
{
    if (!atomic_load(&s_init) || !password || !pmk || !salt || salt_len == 0) {
        return false;
    }

    uint8_t calc[32] = {0};
    pbkdf2_hmac_sha256(password, pwd_len, salt, salt_len, 4096, calc);
    return memcmp(calc, pmk, sizeof(calc)) == 0;
}

bool dragonfly_sim_try_commit(const uint8_t *pwd, size_t pwd_len,
                              const uint8_t *expected_element)
{
    (void)pwd; 
    (void)pwd_len; 
    (void)expected_element;
    return false;
}
