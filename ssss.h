#ifndef SSSS_H
#define SSSS_H

#include <gmp.h>
#include <stddef.h>

#define MAX_SECRET_LEN 512
#define MAX_SHARES 255

/* Fixed primes for different security levels (avoids recording prime) */
#define NUM_FIXED_PRIMES 4
extern const char *FIXED_PRIMES[];
int get_prime_version(int secret_bits);
void get_fixed_prime(mpz_t prime, int version);

typedef struct {
    int index;
    mpz_t value;
} share_t;

typedef struct {
    int threshold;
    int num_shares;
    mpz_t prime;
    share_t *shares;
    int is_bip39;      /* 1 if BIP39 encoding was used */
    int bip39_words;   /* Number of BIP39 words (12, 15, 18, 21, 24) */
} ssss_ctx_t;

/* Initialize/cleanup context */
void ssss_ctx_init(ssss_ctx_t *ctx);
void ssss_ctx_clear(ssss_ctx_t *ctx);

/* Core operations */
int ssss_split(ssss_ctx_t *ctx, const char *secret, int threshold, int num_shares);
int ssss_split_ex(ssss_ctx_t *ctx, const char *secret, int threshold, int num_shares, int use_fixed_prime, int *prime_version_out);
int ssss_combine(char *secret, size_t secret_len, share_t *shares, int num_shares, mpz_t prime);

/* Share I/O */
int share_to_string(char *buf, size_t buf_len, const share_t *share, const mpz_t prime);
int string_to_share(share_t *share, mpz_t prime_out, const char *str);

/* Utility */
int get_security_level(const char *secret);

/* Paper-friendly output (version=0 shows full prime, version>0 shows "V1/V2/V3/V4") */
void print_paper_share(int index, int total, int threshold, const share_t *share, int prime_version);
void print_paper_share_ex(int index, int total, int threshold, const share_t *share, int prime_version, int is_bip39, int bip39_words);

/* BIP39-aware combine: if bip39_words > 0, decode result as BIP39 mnemonic */
int ssss_combine_bip39(char *secret, size_t secret_len, share_t *shares, int num_shares, mpz_t prime, int bip39_words);

#endif /* SSSS_H */
