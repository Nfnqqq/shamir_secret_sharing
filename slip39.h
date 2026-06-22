#ifndef SLIP39_H
#define SLIP39_H

#include <stddef.h>
#include <gmp.h>

#define SLIP39_WORD_COUNT 1024
#define SLIP39_BITS_PER_WORD 10

/* Check if input looks like SLIP39 mnemonic (space-separated known words) */
int is_slip39_mnemonic(const char *input, int *word_count);

/* Encode SLIP39 mnemonic to compact integer (10 bits per word) */
int slip39_encode(mpz_t result, const char *mnemonic);

/* Decode compact integer back to SLIP39 mnemonic */
int slip39_decode(char *mnemonic, size_t max_len, const mpz_t encoded, int word_count);

/* Get required bits for N words */
int slip39_bits_needed(int word_count);

/* Validate mnemonic and report invalid words
 * Returns number of invalid words found (0 = all valid)
 * invalid_words: buffer to store comma-separated list of invalid words (can be NULL)
 * invalid_words_len: size of buffer
 */
int slip39_validate(const char *input, char *invalid_words, size_t invalid_words_len);

#endif /* SLIP39_H */
