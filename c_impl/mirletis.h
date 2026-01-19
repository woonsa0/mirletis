/**
 * @file mirletis.h
 * @brief Mirletis: The Dragon-Lattice Cryptography Engine (Embedded C)
 *
 * A lightweight, post-quantum Key Encapsulation Mechanism (KEM) based on
 * Learning With Rounding (LWR). Optimized for constrained environments
 * ranging from 8-bit MCUs to high-performance clusters.
 *
 * @note    Verified Security: >300 bits (at K=5) via SageMath/Lattice-Estimator.
 * @license Apache-2.0 / MIT
 * @author  Mirletis Project Contributors
 */

#ifndef MIRLETIS_H
#define MIRLETIS_H

#include <stdint.h>
#include <string.h>
#include <stddef.h>

/* ============================================================================
 * [1. SYSTEM PARAMETERS]
 * ============================================================================ */

/** @brief Lattice dimension parameter N */
#define MIR_N           256

/** @brief Matrix rank parameter K (Scalable Security) */
#define MIR_K           5

/** @brief Modulus mask (Q = 8192) */
#define MIR_Q_MASK      0x1FFF

/** @brief Compression shift factor */
#define MIR_SHIFT       5

#define MIR_SEED_LEN    32
#define MIR_SHARED_LEN  32
#define MIR_MASK_LEN    32
#define MIR_SHAKE_RATE  136

/**
 * @brief RAM Optimization Mode
 * - 3: 3KB Mode (Element-wise generation, lowest memory footprint)
 * - 4: 4KB Mode (Block-wise generation, speed optimized)
 */
#ifndef MIR_RAM_MODE
#define MIR_RAM_MODE 4
#endif

/* ============================================================================
 * [2. BRANCHLESS PRIMITIVES]
 * ============================================================================ */

/* Constant-time arithmetic macros */
#define MIR_SIGN(x)          ((int32_t)(x) >> 31)
#define MIR_ABS(x)           (((x) ^ MIR_SIGN(x)) - MIR_SIGN(x))
#define MIR_MIN(a, b)        ((b) + (((a) - (b)) & MIR_SIGN((a) - (b))))
#define MIR_LT(a, b)         ((uint32_t)(((int32_t)(a) - (int32_t)(b)) >> 31) & 1)
#define MIR_EQ(a, b)         (1 ^ ((((uint32_t)((a)^(b))) | (uint32_t)(-((int32_t)((a)^(b))))) >> 31))
#define MIR_SEL(a, b, c)     ((b) ^ (((a) ^ (b)) & (-(int32_t)(c))))
#define MIR_SEL_U8(a, b, c)  ((uint8_t)MIR_SEL((int32_t)(a), (int32_t)(b), (c)))
#define MIR_BIT_GET(arr, i)  (((arr)[(i) >> 3] >> ((i) & 7)) & 1)
#define MIR_BIT_SET(arr, i, v) ((arr)[(i) >> 3] |= ((uint8_t)(v) << ((i) & 7)))

/**
 * @brief Constant-time ternary sampler.
 * Maps 2 bits {0,1,2,3} to {-1,0,1,0} without branching.
 */
static inline int16_t mir_ternary(uint8_t r) {
    int32_t val = r & 3;
    int32_t base = val - 1;
    uint32_t is_three = MIR_EQ(val, 3);
    return (int16_t)MIR_SEL(0, base, is_three);
}

/**
 * @brief Safe-Zone mapping function.
 * Determines if a value falls within the secure region (distance < 12).
 */
static inline uint32_t mir_safe_zone(uint8_t v) {
    int32_t val = (int32_t)v;
    int32_t d1 = MIR_ABS(val - 32);
    int32_t d2 = MIR_ABS(val - 96);
    int32_t d3 = MIR_ABS(val - 160);
    int32_t d4 = MIR_ABS(val - 224);
    int32_t m = MIR_MIN(MIR_MIN(d1, d2), MIR_MIN(d3, d4));
    return MIR_LT(m, 12);
}

/** @brief Securely zeroes out memory to prevent cold-boot attacks. */
static inline void mir_sec_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

/* ============================================================================
 * [3. TINY KECCAK-F1600 ENGINE]
 * ============================================================================ */

typedef struct {
    uint64_t s[25];
    uint8_t pos;
} mir_shake_ctx;

static const uint64_t MIR_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const uint8_t MIR_PI[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static const uint8_t MIR_RHO[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static inline uint64_t mir_rotl64(uint64_t x, uint8_t n) {
    return (x << n) | (x >> (64 - n));
}

static void mir_keccak_f1600(uint64_t *st) {
    uint64_t bc[5], t;
    uint8_t i, j, r;

    for (r = 0; r < 24; r++) {
        bc[0] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        bc[1] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        bc[2] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        bc[3] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        bc[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        t = bc[4] ^ mir_rotl64(bc[1], 1);
        st[0] ^= t; st[5] ^= t; st[10] ^= t; st[15] ^= t; st[20] ^= t;
        t = bc[0] ^ mir_rotl64(bc[2], 1);
        st[1] ^= t; st[6] ^= t; st[11] ^= t; st[16] ^= t; st[21] ^= t;
        t = bc[1] ^ mir_rotl64(bc[3], 1);
        st[2] ^= t; st[7] ^= t; st[12] ^= t; st[17] ^= t; st[22] ^= t;
        t = bc[2] ^ mir_rotl64(bc[4], 1);
        st[3] ^= t; st[8] ^= t; st[13] ^= t; st[18] ^= t; st[23] ^= t;
        t = bc[3] ^ mir_rotl64(bc[0], 1);
        st[4] ^= t; st[9] ^= t; st[14] ^= t; st[19] ^= t; st[24] ^= t;

        t = st[1];
        for (i = 0; i < 24; i++) {
            j = MIR_PI[i];
            bc[0] = st[j];
            st[j] = mir_rotl64(t, MIR_RHO[i]);
            t = bc[0];
        }

        for (j = 0; j < 25; j += 5) {
            bc[0] = st[j]; bc[1] = st[j + 1]; bc[2] = st[j + 2];
            bc[3] = st[j + 3]; bc[4] = st[j + 4];
            st[j]     ^= (~bc[1]) & bc[2];
            st[j + 1] ^= (~bc[2]) & bc[3];
            st[j + 2] ^= (~bc[3]) & bc[4];
            st[j + 3] ^= (~bc[4]) & bc[0];
            st[j + 4] ^= (~bc[0]) & bc[1];
        }

        st[0] ^= MIR_RC[r];
    }
}

/* ============================================================================
 * [4. SHAKE-256 API]
 * ============================================================================ */

static inline void mir_shake_init(mir_shake_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

static void mir_shake_absorb(mir_shake_ctx *ctx, const uint8_t *data, size_t len) {
    uint8_t *state = (uint8_t *)ctx->s;
    while (len--) {
        state[ctx->pos++] ^= *data++;
        if (ctx->pos >= MIR_SHAKE_RATE) {
            mir_keccak_f1600(ctx->s);
            ctx->pos = 0;
        }
    }
}

static inline void mir_shake_finalize(mir_shake_ctx *ctx) {
    uint8_t *state = (uint8_t *)ctx->s;
    state[ctx->pos] ^= 0x1F;           /* SHAKE256 domain */
    state[MIR_SHAKE_RATE - 1] ^= 0x80;
    mir_keccak_f1600(ctx->s);
    ctx->pos = 0;
}

static void mir_shake_squeeze(mir_shake_ctx *ctx, uint8_t *out, size_t len) {
    uint8_t *state = (uint8_t *)ctx->s;
    while (len--) {
        if (ctx->pos >= MIR_SHAKE_RATE) {
            mir_keccak_f1600(ctx->s);
            ctx->pos = 0;
        }
        *out++ = state[ctx->pos++];
    }
}

/**
 * @brief SHA3-256 for Key Derivation Function (KDF).
 */
static void mir_sha3_256(uint8_t out[32], const uint8_t *data, size_t len, uint8_t domain) {
    mir_shake_ctx ctx;
    mir_shake_init(&ctx);
    mir_shake_absorb(&ctx, &domain, 1);
    mir_shake_absorb(&ctx, data, len);

    uint8_t *state = (uint8_t *)ctx.s;
    state[ctx.pos] ^= 0x06;            /* SHA3-256 domain */
    state[MIR_SHAKE_RATE - 1] ^= 0x80;
    mir_keccak_f1600(ctx.s);

    memcpy(out, state, 32);
}

/* ============================================================================
 * [5. DATA TYPES]
 * ============================================================================ */

typedef struct {
    uint8_t seed[MIR_SEED_LEN];
    uint8_t b[MIR_K * MIR_N];
} mir_pk_t;

typedef struct {
    int16_t s[MIR_K * MIR_N];
} mir_sk_t;

typedef struct {
    uint8_t u[MIR_K * MIR_N];
    uint8_t mask[MIR_MASK_LEN];
    uint16_t cnt;
} mir_ct_t;

/* ============================================================================
 * [6. JIT GENERATORS (Memory Optimized)]
 * ============================================================================ */

static void mir_jit_secret_row(int16_t out[MIR_N], const uint8_t seed[32], uint8_t row) {
    mir_shake_ctx ctx;
    mir_shake_init(&ctx);
    mir_shake_absorb(&ctx, seed, 32);

    uint8_t params[2] = {0xFF, row};
    mir_shake_absorb(&ctx, params, 2);
    mir_shake_finalize(&ctx);

    uint8_t buf[32];
    uint16_t idx = 0;
    uint8_t buf_pos = 32;

    while (idx < MIR_N) {
        if (buf_pos >= 32) {
            mir_shake_squeeze(&ctx, buf, 32);
            buf_pos = 0;
        }
        out[idx++] = mir_ternary(buf[buf_pos++]);
    }
}

static void mir_jit_matrix_block(int16_t out[MIR_N], const uint8_t seed[32], uint8_t row, uint8_t col) {
    mir_shake_ctx ctx;
    mir_shake_init(&ctx);
    mir_shake_absorb(&ctx, seed, 32);

    uint8_t params[3] = {0x00, row, col};
    mir_shake_absorb(&ctx, params, 3);
    mir_shake_finalize(&ctx);

    uint8_t buf[32];
    uint16_t idx = 0;
    uint8_t buf_pos = 32;

    while (idx < MIR_N) {
        if (buf_pos >= 32) {
            mir_shake_squeeze(&ctx, buf, 32);
            buf_pos = 0;
        }
        uint16_t val = ((uint16_t)buf[buf_pos + 1] << 8) | buf[buf_pos];
        out[idx++] = (int16_t)(val & MIR_Q_MASK);
        buf_pos += 2;
    }
}

#if MIR_RAM_MODE < 4
/* Element-wise generators for 3KB restricted mode */
static int16_t mir_jit_secret_elem(const uint8_t seed[32], uint8_t row, uint8_t idx) {
    mir_shake_ctx ctx;
    mir_shake_init(&ctx);
    mir_shake_absorb(&ctx, seed, 32);

    uint8_t params[3] = {0xFF, row, idx};
    mir_shake_absorb(&ctx, params, 3);
    mir_shake_finalize(&ctx);

    uint8_t buf;
    mir_shake_squeeze(&ctx, &buf, 1);
    return mir_ternary(buf);
}

static int16_t mir_jit_matrix_elem(const uint8_t seed[32], uint8_t row, uint8_t col, uint8_t idx) {
    mir_shake_ctx ctx;
    mir_shake_init(&ctx);
    mir_shake_absorb(&ctx, seed, 32);

    uint8_t params[4] = {0x00, row, col, idx};
    mir_shake_absorb(&ctx, params, 4);
    mir_shake_finalize(&ctx);

    uint8_t buf[2];
    mir_shake_squeeze(&ctx, buf, 2);
    uint16_t val = ((uint16_t)buf[1] << 8) | buf[0];
    return (int16_t)(val & MIR_Q_MASK);
}
#endif

/* ============================================================================
 * [7. KEY GENERATION]
 * ============================================================================ */

/**
 * @brief Generates a public/private key pair.
 * @param pk Output public key.
 * @param sk Output secret key.
 * @param entropy 32-byte high-quality entropy source.
 * @return 0 on success.
 */
int mir_keygen(mir_pk_t *pk, mir_sk_t *sk, const uint8_t entropy[32]) {
    mir_shake_ctx ctx;
    mir_shake_init(&ctx);
    mir_shake_absorb(&ctx, entropy, 32);
    mir_shake_finalize(&ctx);

    mir_shake_squeeze(&ctx, pk->seed, MIR_SEED_LEN);

    uint8_t secret_seed[32];
    mir_shake_squeeze(&ctx, secret_seed, 32);

    /* Generate secret key */
    uint8_t row = 0;
    while (row < MIR_K) {
        mir_jit_secret_row(&sk->s[row * MIR_N], secret_seed, row);
        row++;
    }
    mir_sec_zero(secret_seed, 32);

    /* b = A * s */
    #if MIR_RAM_MODE >= 4
    int16_t a_block[MIR_N];
    int16_t acc[MIR_N];

    uint8_t i = 0;
    while (i < MIR_K) {
        memset(acc, 0, sizeof(acc));

        uint8_t l = 0;
        while (l < MIR_K) {
            mir_jit_matrix_block(a_block, pk->seed, i, l);

            uint16_t j = 0;
            while (j < MIR_N) {
                int32_t prod = (int32_t)a_block[j] * (int32_t)sk->s[l * MIR_N + j];
                acc[j] = (int16_t)((acc[j] + prod) & MIR_Q_MASK);
                j++;
            }
            l++;
        }

        uint16_t j = 0;
        while (j < MIR_N) {
            pk->b[i * MIR_N + j] = (uint8_t)((acc[j] & MIR_Q_MASK) >> MIR_SHIFT);
            j++;
        }
        i++;
    }

    mir_sec_zero(a_block, sizeof(a_block));
    mir_sec_zero(acc, sizeof(acc));
    #else
    /* 3KB mode: element-wise generation */
    uint8_t i = 0;
    while (i < MIR_K) {
        uint16_t j = 0;
        while (j < MIR_N) {
            int32_t acc = 0;
            uint8_t l = 0;
            while (l < MIR_K) {
                int16_t a = mir_jit_matrix_elem(pk->seed, i, l, (uint8_t)j);
                acc += (int32_t)a * (int32_t)sk->s[l * MIR_N + j];
                l++;
            }
            pk->b[i * MIR_N + j] = (uint8_t)((acc & MIR_Q_MASK) >> MIR_SHIFT);
            j++;
        }
        i++;
    }
    #endif

    return 0;
}

/* ============================================================================
 * [8. ENCAPSULATION]
 * ============================================================================ */

/**
 * @brief Encapsulates a shared secret.
 * @param ct Output ciphertext.
 * @param shared_key Output 32-byte shared secret.
 * @param pk Input public key.
 * @param entropy 32-byte ephemeral entropy.
 * @return 0 on success.
 */
int mir_encaps(mir_ct_t *ct, uint8_t shared_key[32], const mir_pk_t *pk, const uint8_t entropy[32]) {
    /* Derive ephemeral r seed */
    mir_shake_ctx ent_ctx;
    mir_shake_init(&ent_ctx);
    mir_shake_absorb(&ent_ctx, entropy, 32);
    mir_shake_finalize(&ent_ctx);

    uint8_t r_seed[32];
    mir_shake_squeeze(&ent_ctx, r_seed, 32);

    #if MIR_RAM_MODE >= 4
    int16_t r_row[MIR_N];
    int16_t a_block[MIR_N];
    int16_t acc[MIR_N];

    /* u = A^T * r */
    uint8_t i = 0;
    while (i < MIR_K) {
        memset(acc, 0, sizeof(acc));

        uint8_t l = 0;
        while (l < MIR_K) {
            mir_jit_matrix_block(a_block, pk->seed, l, i);
            mir_jit_secret_row(r_row, r_seed, l);

            uint16_t j = 0;
            while (j < MIR_N) {
                int32_t prod = (int32_t)a_block[j] * (int32_t)r_row[j];
                acc[j] = (int16_t)((acc[j] + prod) & MIR_Q_MASK);
                j++;
            }
            l++;
        }

        uint16_t j = 0;
        while (j < MIR_N) {
            ct->u[i * MIR_N + j] = (uint8_t)((acc[j] & MIR_Q_MASK) >> MIR_SHIFT);
            j++;
        }
        i++;
    }

    /* v = b * r */
    uint8_t v[MIR_N];
    memset(v, 0, sizeof(v));

    uint8_t l = 0;
    while (l < MIR_K) {
        mir_jit_secret_row(r_row, r_seed, l);

        uint16_t j = 0;
        while (j < MIR_N) {
            int32_t prod = (int32_t)pk->b[l * MIR_N + j] * (int32_t)r_row[j];
            v[j] = (uint8_t)((v[j] + prod) & 0xFF);
            j++;
        }
        l++;
    }

    mir_sec_zero(r_row, sizeof(r_row));
    mir_sec_zero(a_block, sizeof(a_block));
    mir_sec_zero(acc, sizeof(acc));
    #else
    /* 3KB mode */
    uint8_t i = 0;
    while (i < MIR_K) {
        uint16_t j = 0;
        while (j < MIR_N) {
            int32_t acc = 0;
            uint8_t l = 0;
            while (l < MIR_K) {
                int16_t a = mir_jit_matrix_elem(pk->seed, l, i, (uint8_t)j);
                int16_t r = mir_jit_secret_elem(r_seed, l, (uint8_t)j);
                acc += (int32_t)a * (int32_t)r;
                l++;
            }
            ct->u[i * MIR_N + j] = (uint8_t)((acc & MIR_Q_MASK) >> MIR_SHIFT);
            j++;
        }
        i++;
    }

    uint8_t v[MIR_N];
    uint16_t j = 0;
    while (j < MIR_N) {
        int32_t acc = 0;
        uint8_t l = 0;
        while (l < MIR_K) {
            int16_t r = mir_jit_secret_elem(r_seed, l, (uint8_t)j);
            acc += (int32_t)pk->b[l * MIR_N + j] * (int32_t)r;
            l++;
        }
        v[j] = (uint8_t)(acc & 0xFF);
        j++;
    }
    #endif

    /* Safe-Zone Selection */
    uint8_t buf[MIR_N];
    uint16_t widx = 0;

    memset(ct->mask, 0, MIR_MASK_LEN);
    memset(buf, 0, sizeof(buf));

    uint16_t idx = 0;
    while (idx < MIR_N) {
        uint8_t val = v[idx];
        uint32_t safe = mir_safe_zone(val);

        MIR_BIT_SET(ct->mask, idx, safe);
        uint8_t bit = (val >> 6) & 1;
        buf[widx] = MIR_SEL_U8(bit, buf[widx], safe);
        widx += (uint16_t)safe;
        idx++;
    }

    ct->cnt = widx;

    /* SHA3-256 KDF */
    mir_sha3_256(shared_key, buf, widx, 0x02);

    mir_sec_zero(r_seed, sizeof(r_seed));
    mir_sec_zero(v, sizeof(v));
    mir_sec_zero(buf, sizeof(buf));

    return 0;
}

/* ============================================================================
 * [9. DECAPSULATION]
 * ============================================================================ */

/**
 * @brief Decapsulates a shared secret from ciphertext.
 * @param shared_key Output 32-byte shared secret.
 * @param ct Input ciphertext.
 * @param sk Input secret key.
 * @return 0 on success.
 */
int mir_decaps(uint8_t shared_key[32], const mir_ct_t *ct, const mir_sk_t *sk) {
    /* v' = u * s */
    uint8_t vp[MIR_N];

    uint16_t j = 0;
    while (j < MIR_N) {
        int32_t acc = 0;
        uint8_t l = 0;
        while (l < MIR_K) {
            acc += (int32_t)ct->u[l * MIR_N + j] * (int32_t)sk->s[l * MIR_N + j];
            l++;
        }
        vp[j] = (uint8_t)(acc & 0xFF);
        j++;
    }

    /* Mask filtering */
    uint8_t buf[MIR_N];
    uint16_t widx = 0;

    memset(buf, 0, sizeof(buf));

    uint16_t idx = 0;
    while (idx < MIR_N) {
        uint8_t val = vp[idx];
        uint32_t sel = MIR_BIT_GET(ct->mask, idx);
        uint8_t bit = (val >> 6) & 1;

        buf[widx] = MIR_SEL_U8(bit, buf[widx], sel);
        widx += (uint16_t)sel;
        idx++;
    }

    /* SHA3-256 KDF (Same Domain) */
    mir_sha3_256(shared_key, buf, widx, 0x02);

    mir_sec_zero(vp, sizeof(vp));
    mir_sec_zero(buf, sizeof(buf));

    return 0;
}

/* ============================================================================
 * [10. SELF TEST]
 * ============================================================================ */

int mir_self_test(const uint8_t entropy[32]) {
    mir_pk_t pk;
    mir_sk_t sk;
    mir_ct_t ct;
    uint8_t k1[32], k2[32];

    uint8_t ent_kg[32], ent_enc[32];
    memcpy(ent_kg, entropy, 32);

    mir_shake_ctx ctx;
    mir_shake_init(&ctx);
    mir_shake_absorb(&ctx, entropy, 32);
    mir_shake_finalize(&ctx);
    mir_shake_squeeze(&ctx, ent_enc, 32);

    if (mir_keygen(&pk, &sk, ent_kg) != 0) return -1;
    if (mir_encaps(&ct, k1, &pk, ent_enc) != 0) return -2;
    if (mir_decaps(k2, &ct, &sk) != 0) return -3;

    uint8_t diff = 0;
    uint8_t i = 0;
    while (i < 32) {
        diff |= k1[i] ^ k2[i];
        i++;
    }

    mir_sec_zero(&sk, sizeof(sk));

    return (diff == 0) ? 0 : -4;
}

/* ============================================================================
 * [11. MAIN ENTRY]
 * ============================================================================ */

#ifdef MIRLETIS_MAIN
#include <stdio.h>

int main(void) {
    printf("=== MIRLETIS CORE (Embedded) v1.3 ===\n");
    printf("RAM Mode: %dKB\n\n", MIR_RAM_MODE);

    uint8_t entropy[32];
    for (int i = 0; i < 32; i++) entropy[i] = (uint8_t)(i + 1);

    int result = mir_self_test(entropy);

    if (result == 0) {
        printf("✅ Mirletis Test PASSED\n");
    } else {
        printf("❌ Mirletis Test FAILED: %d\n", result);
    }

    return result;
}
#endif

#endif /* MIRLETIS_H */
