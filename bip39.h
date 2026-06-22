#ifndef BIP39_H
#define BIP39_H

#include <stddef.h>
#include <gmp.h>

#define BIP39_WORD_COUNT 2048
#define BIP39_BITS_PER_WORD 11

/* Check if input looks like BIP39 mnemonic (space-separated known words) */
int is_bip39_mnemonic(const char *input, int *word_count);

/* Encode BIP39 mnemonic to compact integer (11 bits per word) */
int bip39_encode(mpz_t result, const char *mnemonic);

/* Decode compact integer back to BIP39 mnemonic */
int bip39_decode(char *mnemonic, size_t max_len, const mpz_t encoded, int word_count);

/* Get required bits for N words */
int bip39_bits_needed(int word_count);

#endif /* BIP39_H */
