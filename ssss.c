#include "ssss.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * Fixed primes for paper-friendly format (no need to record prime)
 * Version 1: 256-bit  - for secrets up to 192 bits (~24 chars)
 * Version 2: 512-bit  - for secrets up to 448 bits (~56 chars)
 * Version 3: 1536-bit - for secrets up to 1472 bits (~184 chars, covers 24-word seeds)
 * These are verifiable primes: 2^n - k for small k
 */
const char *FIXED_PRIMES[] = {
    /* V1: 2^256 - 189 (256-bit prime) */
    "115792089237316195423570985008687907853269984665640564039457584007913129639747",
    /* V2: 2^512 - 38117 (512-bit prime) */
    "13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171",
    /* V3: 2^1536 - 1177 (1536-bit prime, covers 24-word BIP39 seeds with margin) */
    "2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919"
};

int get_prime_version(int secret_bits) {
    (void)secret_bits;  /* Always use V3 for simplicity */
    return 3;
}

void get_fixed_prime(mpz_t prime, int version) {
    if (version < 1 || version > NUM_FIXED_PRIMES) version = 3;
    mpz_set_str(prime, FIXED_PRIMES[version - 1], 10);
}

static int read_random_bytes(unsigned char *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;

    ssize_t n = read(fd, buf, len);
    close(fd);

    return (n == (ssize_t)len) ? 0 : -1;
}

static void generate_random_mpz(mpz_t result, const mpz_t max) {
    size_t bits = mpz_sizeinbase(max, 2);
    size_t bytes = (bits + 7) / 8;
    unsigned char *buf = malloc(bytes);

    do {
        read_random_bytes(buf, bytes);
        mpz_import(result, bytes, 1, 1, 0, 0, buf);
        mpz_mod(result, result, max);
    } while (mpz_cmp_ui(result, 0) == 0);

    free(buf);
}

static void generate_prime(mpz_t prime, int bits) {
    mpz_t candidate;
    mpz_init(candidate);

    size_t bytes = (bits + 7) / 8;
    unsigned char *buf = malloc(bytes);

    do {
        read_random_bytes(buf, bytes);
        buf[0] |= 0x80;  /* Ensure high bit is set */
        buf[bytes - 1] |= 0x01;  /* Ensure odd */
        mpz_import(candidate, bytes, 1, 1, 0, 0, buf);
        mpz_nextprime(prime, candidate);
    } while (mpz_sizeinbase(prime, 2) < (size_t)bits);

    free(buf);
    mpz_clear(candidate);
}

/* Evaluate polynomial at x: f(x) = coeffs[0] + coeffs[1]*x + ... + coeffs[degree]*x^degree */
static void eval_polynomial(mpz_t result, mpz_t *coeffs, int degree, int x, const mpz_t prime) {
    mpz_t term, x_pow, x_mpz;
    mpz_inits(term, x_pow, x_mpz, NULL);
    mpz_set_ui(x_mpz, x);
    mpz_set_ui(x_pow, 1);
    mpz_set_ui(result, 0);

    for (int i = 0; i <= degree; i++) {
        mpz_mul(term, coeffs[i], x_pow);
        mpz_add(result, result, term);
        mpz_mod(result, result, prime);
        mpz_mul(x_pow, x_pow, x_mpz);
        mpz_mod(x_pow, x_pow, prime);
    }

    mpz_clears(term, x_pow, x_mpz, NULL);
}

void ssss_ctx_init(ssss_ctx_t *ctx) {
    ctx->threshold = 0;
    ctx->num_shares = 0;
    ctx->shares = NULL;
    mpz_init(ctx->prime);
}

void ssss_ctx_clear(ssss_ctx_t *ctx) {
    if (ctx->shares) {
        for (int i = 0; i < ctx->num_shares; i++) {
            mpz_clear(ctx->shares[i].value);
        }
        free(ctx->shares);
        ctx->shares = NULL;
    }
    mpz_clear(ctx->prime);
}

int get_security_level(const char *secret) {
    size_t len = strlen(secret);
    return (int)(len * 8);
}

int ssss_split_ex(ssss_ctx_t *ctx, const char *secret, int threshold, int num_shares, int use_fixed_prime, int *prime_version_out) {
    if (threshold < 2 || threshold > num_shares || num_shares > MAX_SHARES) {
        return -1;
    }

    size_t secret_len = strlen(secret);
    if (secret_len == 0 || secret_len > MAX_SECRET_LEN) {
        return -1;
    }

    ctx->threshold = threshold;
    ctx->num_shares = num_shares;

    /* Convert secret to big integer */
    mpz_t secret_int;
    mpz_init(secret_int);
    mpz_import(secret_int, secret_len, 1, 1, 0, 0, secret);

    int secret_bits = mpz_sizeinbase(secret_int, 2);

    if (use_fixed_prime) {
        /* Use fixed prime based on secret size */
        int version = get_prime_version(secret_bits);
        get_fixed_prime(ctx->prime, version);
        if (prime_version_out) *prime_version_out = version;
    } else {
        /* Generate random prime larger than secret */
        int prime_bits = secret_bits + 64;
        generate_prime(ctx->prime, prime_bits);
        if (prime_version_out) *prime_version_out = 0;
    }

    /* Create polynomial coefficients: f(x) = secret + a1*x + a2*x^2 + ... */
    mpz_t *coeffs = malloc(threshold * sizeof(mpz_t));
    for (int i = 0; i < threshold; i++) {
        mpz_init(coeffs[i]);
    }
    mpz_set(coeffs[0], secret_int);  /* Constant term is the secret */

    /* Generate random coefficients for higher terms */
    for (int i = 1; i < threshold; i++) {
        generate_random_mpz(coeffs[i], ctx->prime);
    }

    /* Allocate shares */
    ctx->shares = malloc(num_shares * sizeof(share_t));
    for (int i = 0; i < num_shares; i++) {
        ctx->shares[i].index = i + 1;  /* 1-indexed */
        mpz_init(ctx->shares[i].value);
        eval_polynomial(ctx->shares[i].value, coeffs, threshold - 1, i + 1, ctx->prime);
    }

    /* Cleanup */
    for (int i = 0; i < threshold; i++) {
        mpz_clear(coeffs[i]);
    }
    free(coeffs);
    mpz_clear(secret_int);

    return 0;
}

/* Backward compatible wrapper */
int ssss_split(ssss_ctx_t *ctx, const char *secret, int threshold, int num_shares) {
    return ssss_split_ex(ctx, secret, threshold, num_shares, 0, NULL);
}

/* Lagrange interpolation to find f(0) */
int ssss_combine(char *secret, size_t secret_len, share_t *shares, int num_shares, mpz_t prime) {
    mpz_t result, term, num, den, inv, xi, xj;
    mpz_inits(result, term, num, den, inv, xi, xj, NULL);
    mpz_set_ui(result, 0);

    for (int i = 0; i < num_shares; i++) {
        mpz_set_ui(num, 1);
        mpz_set_ui(den, 1);
        mpz_set_ui(xi, shares[i].index);

        for (int j = 0; j < num_shares; j++) {
            if (i == j) continue;
            mpz_set_ui(xj, shares[j].index);

            /* num *= -xj (mod prime) = (prime - xj) */
            mpz_sub(term, prime, xj);
            mpz_mul(num, num, term);
            mpz_mod(num, num, prime);

            /* den *= (xi - xj) */
            mpz_sub(term, xi, xj);
            mpz_mod(term, term, prime);
            mpz_mul(den, den, term);
            mpz_mod(den, den, prime);
        }

        /* term = shares[i].value * num * den^(-1) */
        if (mpz_invert(inv, den, prime) == 0) {
            mpz_clears(result, term, num, den, inv, xi, xj, NULL);
            return -1;  /* No inverse exists */
        }

        mpz_mul(term, shares[i].value, num);
        mpz_mod(term, term, prime);
        mpz_mul(term, term, inv);
        mpz_mod(term, term, prime);

        mpz_add(result, result, term);
        mpz_mod(result, result, prime);
    }

    /* Convert result back to string */
    size_t count;
    unsigned char *bytes = mpz_export(NULL, &count, 1, 1, 0, 0, result);

    if (count >= secret_len) {
        free(bytes);
        mpz_clears(result, term, num, den, inv, xi, xj, NULL);
        return -1;
    }

    memcpy(secret, bytes, count);
    secret[count] = '\0';
    free(bytes);

    mpz_clears(result, term, num, den, inv, xi, xj, NULL);
    return 0;
}

int share_to_string(char *buf, size_t buf_len, const share_t *share, const mpz_t prime) {
    char *prime_hex = mpz_get_str(NULL, 16, prime);
    char *value_hex = mpz_get_str(NULL, 16, share->value);
    int n = snprintf(buf, buf_len, "%d-%s-%s", share->index, prime_hex, value_hex);
    free(prime_hex);
    free(value_hex);
    return (n > 0 && (size_t)n < buf_len) ? 0 : -1;
}

/* Calculate checksum: sum of all digits mod 97 */
static int calc_checksum(const char *digits) {
    int sum = 0;
    for (int i = 0; digits[i]; i++) {
        if (digits[i] >= '0' && digits[i] <= '9') {
            sum += digits[i] - '0';
        }
    }
    return sum % 97;
}

/* Format decimal string with spaces every 5 digits */
static void format_grouped(char *out, const char *digits, int group_size) {
    int len = strlen(digits);
    int j = 0;
    for (int i = 0; i < len; i++) {
        out[j++] = digits[i];
        if ((i + 1) % group_size == 0 && i + 1 < len) {
            out[j++] = ' ';
        }
    }
    out[j] = '\0';
}

void print_paper_share(int index, int total, int threshold, const share_t *share, int prime_version) {
    char *value_dec = mpz_get_str(NULL, 10, share->value);
    size_t value_len = strlen(value_dec);
    char *value_fmt = malloc(value_len * 2);
    format_grouped(value_fmt, value_dec, 5);

    (void)prime_version;  /* Always V3, no need to display */
    printf("\n");
    printf("┌────────────────────────────────────────┐\n");
    printf("│ SHARE %d of %d              (need %d)  │\n", index, total, threshold);
    printf("├────────────────────────────────────────┤\n");

    /* Print value in lines of ~38 chars */
    char *p = value_fmt;
    while (*p) {
        printf("│ ");
        int count = 0;
        while (*p && count < 36) {
            putchar(*p++);
            count++;
        }
        while (count++ < 36) putchar(' ');
        printf(" │\n");
    }
    printf("├────────────────────────────────────────┤\n");
    printf("│ Checksum: %02d                          │\n", calc_checksum(value_dec));
    printf("└────────────────────────────────────────┘\n");

    free(value_dec);
    free(value_fmt);
}

int string_to_share(share_t *share, mpz_t prime_out, const char *str) {
    /* Format: index-primehex-valuehex */
    char *first_dash = strchr(str, '-');
    if (!first_dash) return -1;

    share->index = atoi(str);
    if (share->index < 1 || share->index > MAX_SHARES) return -1;

    char *second_dash = strchr(first_dash + 1, '-');
    if (!second_dash) return -1;

    /* Extract prime */
    size_t prime_len = second_dash - (first_dash + 1);
    char *prime_str = malloc(prime_len + 1);
    memcpy(prime_str, first_dash + 1, prime_len);
    prime_str[prime_len] = '\0';

    if (mpz_set_str(prime_out, prime_str, 16) != 0) {
        free(prime_str);
        return -1;
    }
    free(prime_str);

    /* Extract value */
    mpz_init(share->value);
    if (mpz_set_str(share->value, second_dash + 1, 16) != 0) {
        mpz_clear(share->value);
        return -1;
    }

    return 0;
}
