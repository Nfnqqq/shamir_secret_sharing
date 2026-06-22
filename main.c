#include "ssss.h"
#include "bip39.h"
#include "slip39.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <ctype.h>

static void print_usage_split(const char *prog) {
    fprintf(stderr, "Usage: %s -t <threshold> -n <num_shares>\n", prog);
    fprintf(stderr, "  -t  Number of shares needed to reconstruct (threshold)\n");
    fprintf(stderr, "  -n  Total number of shares to generate\n");
}

static void print_usage_combine(const char *prog) {
    fprintf(stderr, "Usage: %s -t <threshold>\n", prog);
    fprintf(stderr, "  -t  Number of shares to combine\n");
}

static int read_secret(char *buf, size_t buf_len) {
    printf("Enter secret: ");
    fflush(stdout);

    if (fgets(buf, buf_len, stdin) == NULL) {
        return -1;
    }

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }

    return 0;
}

/* Count words in input (space-separated tokens) */
static int count_words(const char *input) {
    char *copy = strdup(input);
    char *saveptr;
    int count = 0;

    char *token = strtok_r(copy, " \t\n", &saveptr);
    while (token) {
        count++;
        token = strtok_r(NULL, " \t\n", &saveptr);
    }
    free(copy);
    return count;
}

/* Check if input looks like a mnemonic (all tokens are alphabetic words) */
static int looks_like_mnemonic(const char *input) {
    char *copy = strdup(input);
    char *saveptr;
    int looks_like = 1;
    int word_count = 0;

    char *token = strtok_r(copy, " \t\n", &saveptr);
    while (token && looks_like) {
        /* Check if token is all alphabetic */
        for (char *p = token; *p && looks_like; p++) {
            if (!isalpha(*p)) {
                looks_like = 0;
            }
        }
        word_count++;
        token = strtok_r(NULL, " \t\n", &saveptr);
    }
    free(copy);

    /* Must have at least 3 words to look like a mnemonic */
    return looks_like && word_count >= 3;
}

static int do_split(int threshold, int num_shares) {
    char secret[MAX_SECRET_LEN + 2];

    if (read_secret(secret, sizeof(secret)) != 0) {
        fprintf(stderr, "Error reading secret\n");
        return 1;
    }

    if (strlen(secret) == 0) {
        fprintf(stderr, "Error: empty secret\n");
        return 1;
    }

    /* Validate mnemonic input if it looks like one */
    if (looks_like_mnemonic(secret)) {
        int word_count = count_words(secret);
        char invalid_words[512];
        int bip39_invalid = bip39_validate(secret, invalid_words, sizeof(invalid_words));
        int slip39_invalid = slip39_validate(secret, invalid_words, sizeof(invalid_words));

        /* Check if it's a valid BIP39 mnemonic */
        int is_valid_bip39 = (bip39_invalid == 0) &&
                             (word_count == 12 || word_count == 15 ||
                              word_count == 18 || word_count == 21 || word_count == 24);

        /* Check if it's a valid SLIP39 mnemonic */
        int is_valid_slip39 = (slip39_invalid == 0) && (word_count >= 3);

        if (!is_valid_bip39 && !is_valid_slip39) {
            fprintf(stderr, "\nWARNING: Input looks like a mnemonic but contains invalid words!\n");

            /* Show which wordlist has fewer invalid words */
            if (bip39_invalid <= slip39_invalid && bip39_invalid > 0) {
                bip39_validate(secret, invalid_words, sizeof(invalid_words));
                fprintf(stderr, "  Invalid BIP39 words: %s\n", invalid_words);
            }
            if (slip39_invalid <= bip39_invalid && slip39_invalid > 0) {
                slip39_validate(secret, invalid_words, sizeof(invalid_words));
                fprintf(stderr, "  Invalid SLIP39 words: %s\n", invalid_words);
            }

            if (word_count != 12 && word_count != 15 && word_count != 18 &&
                word_count != 21 && word_count != 24 && word_count != 20 && word_count != 33) {
                fprintf(stderr, "  Word count %d is unusual (BIP39: 12/15/18/21/24, SLIP39: typically 20 or 33)\n", word_count);
            }

            fprintf(stderr, "\n  This will be treated as RAW TEXT, not a mnemonic.\n");
            fprintf(stderr, "  [C]ontinue as raw text, [A]bort? ");
            fflush(stderr);

            char line[64];
            if (fgets(line, sizeof(line), stdin) == NULL || line[0] == 'A' || line[0] == 'a') {
                fprintf(stderr, "Aborted.\n");
                return 1;
            }
            fprintf(stderr, "  Continuing as raw text...\n\n");
        }
    }

    ssss_ctx_t ctx;
    ssss_ctx_init(&ctx);

    int prime_version = 0;
    if (ssss_split_ex(&ctx, secret, threshold, num_shares, 1, &prime_version) != 0) {
        fprintf(stderr, "Error splitting secret\n");
        ssss_ctx_clear(&ctx);
        return 1;
    }

    for (int i = 0; i < num_shares; i++) {
        print_paper_share_full(i + 1, num_shares, threshold, &ctx.shares[i], prime_version, ctx.is_bip39, ctx.bip39_words, ctx.is_slip39, ctx.slip39_words);
    }

    memset(secret, 0, sizeof(secret));
    ssss_ctx_clear(&ctx);

    return 0;
}

static void remove_spaces(char *str) {
    char *dst = str;
    for (char *src = str; *src; src++) {
        if (*src != ' ' && *src != '\t') {
            *dst++ = *src;
        }
    }
    *dst = '\0';
}

static int read_line(char *buf, size_t len) {
    if (fgets(buf, len, stdin) == NULL) return -1;
    size_t l = strlen(buf);
    while (l > 0 && (buf[l-1] == '\n' || buf[l-1] == '\r' || buf[l-1] == ' ')) {
        buf[--l] = '\0';
    }
    return 0;
}

static int do_combine(int threshold) {
    share_t *shares = malloc(threshold * sizeof(share_t));
    mpz_t prime;
    mpz_init(prime);

    char line[4096];
    int share_count = 0;
    int bip39_words = 0;
    int slip39_words = 0;

    /* Ask for mode: BIP39 word count, SLIP39 word count, or version */
    printf("Mode (B12/B15/B18/B21/B24 for BIP39, S<n> for SLIP39, or V1/V2/V3/V4 for text): ");
    fflush(stdout);
    if (read_line(line, sizeof(line)) != 0) {
        fprintf(stderr, "Error reading mode\n");
        goto error;
    }

    int version = 0;
    if (line[0] == 'B' || line[0] == 'b') {
        /* BIP39 mode */
        bip39_words = atoi(line + 1);
        if (bip39_words != 12 && bip39_words != 15 && bip39_words != 18 &&
            bip39_words != 21 && bip39_words != 24) {
            fprintf(stderr, "Invalid BIP39 word count (must be 12, 15, 18, 21, or 24)\n");
            goto error;
        }
        /* Select prime based on word count */
        if (bip39_words <= 15) version = 1;      /* 256-bit */
        else version = 2;                         /* 320-bit */
    } else if (line[0] == 'S' || line[0] == 's') {
        /* SLIP39 mode */
        slip39_words = atoi(line + 1);
        if (slip39_words < 3) {
            fprintf(stderr, "Invalid SLIP39 word count (must be at least 3)\n");
            goto error;
        }
        /* Select prime based on word count (10 bits per word) */
        int bits_needed = slip39_words * 10;
        if (bits_needed <= 192) version = 1;
        else if (bits_needed <= 264) version = 2;
        else if (bits_needed <= 448) version = 3;
        else version = 4;
    } else if (line[0] == 'V' || line[0] == 'v') {
        version = atoi(line + 1);
    } else {
        version = atoi(line);
    }

    if (version < 1 || version > 4) {
        fprintf(stderr, "Invalid version (must be 1, 2, 3, or 4)\n");
        goto error;
    }
    get_fixed_prime(prime, version);

    for (int i = 0; i < threshold; i++) {
reenter_share:
        printf("Share %d of %d:\n", i + 1, threshold);

        printf("  Index: ");
        fflush(stdout);
        if (read_line(line, sizeof(line)) != 0) {
            fprintf(stderr, "Error reading index\n");
            goto error;
        }
        shares[i].index = atoi(line);
        if (shares[i].index < 1 || shares[i].index > MAX_SHARES) {
            fprintf(stderr, "Invalid index\n");
            goto error;
        }

        printf("  Value: ");
        fflush(stdout);
        if (read_line(line, sizeof(line)) != 0) {
            fprintf(stderr, "Error reading value\n");
            goto error;
        }
        remove_spaces(line);

        /* Store the value string for checksum calculation */
        char value_str[4096];
        strncpy(value_str, line, sizeof(value_str) - 1);
        value_str[sizeof(value_str) - 1] = '\0';

        mpz_init(shares[i].value);
        if (mpz_set_str(shares[i].value, line, 10) != 0) {
            fprintf(stderr, "Error parsing value\n");
            mpz_clear(shares[i].value);
            goto error;
        }

        /* Prompt for and verify checksum */
        printf("  Checksum: ");
        fflush(stdout);
        if (read_line(line, sizeof(line)) != 0) {
            fprintf(stderr, "Error reading checksum\n");
            mpz_clear(shares[i].value);
            goto error;
        }

        int entered_checksum = atoi(line);
        int calculated_checksum = calc_checksum(value_str);

        if (entered_checksum != calculated_checksum) {
            fprintf(stderr, "\n  WARNING: Checksum mismatch!\n");
            fprintf(stderr, "    Entered:    %02d\n", entered_checksum);
            fprintf(stderr, "    Calculated: %02d\n", calculated_checksum);
            fprintf(stderr, "\n  This likely means there's a typo in the share value.\n");
            fprintf(stderr, "  [R]e-enter share, [C]ontinue anyway, [A]bort? ");
            fflush(stderr);

            if (read_line(line, sizeof(line)) != 0) {
                mpz_clear(shares[i].value);
                goto error;
            }

            if (line[0] == 'R' || line[0] == 'r') {
                mpz_clear(shares[i].value);
                goto reenter_share;
            } else if (line[0] == 'A' || line[0] == 'a') {
                fprintf(stderr, "Aborted.\n");
                mpz_clear(shares[i].value);
                goto error;
            }
            /* Continue anyway if 'C' or anything else */
            fprintf(stderr, "  Continuing with potentially incorrect share...\n\n");
        }

        share_count++;
    }

    char secret[MAX_SECRET_LEN + 1];
    if (ssss_combine_mnemonic(secret, sizeof(secret), shares, threshold, prime, bip39_words, slip39_words) != 0) {
        fprintf(stderr, "Error combining shares\n");
        goto error;
    }

    printf("\nRecovered secret: %s\n", secret);

    memset(secret, 0, sizeof(secret));
    for (int i = 0; i < share_count; i++) {
        mpz_clear(shares[i].value);
    }
    free(shares);
    mpz_clear(prime);

    return 0;

error:
    for (int i = 0; i < share_count; i++) {
        mpz_clear(shares[i].value);
    }
    free(shares);
    mpz_clear(prime);
    return 1;
}

int main(int argc, char *argv[]) {
    char *prog = basename(argv[0]);
    int is_split = (strstr(prog, "split") != NULL);
    int is_combine = (strstr(prog, "combine") != NULL);

    if (!is_split && !is_combine) {
        if (argc > 1 && strcmp(argv[1], "combine") == 0) {
            is_combine = 1;
            argc--;
            argv++;
        } else {
            is_split = 1;
        }
    }

    int threshold = 0;
    int num_shares = 0;
    int opt;

    while ((opt = getopt(argc, argv, "t:n:h")) != -1) {
        switch (opt) {
            case 't':
                threshold = atoi(optarg);
                break;
            case 'n':
                num_shares = atoi(optarg);
                break;
            case 'h':
            default:
                if (is_split) {
                    print_usage_split(prog);
                } else {
                    print_usage_combine(prog);
                }
                return (opt == 'h') ? 0 : 1;
        }
    }

    if (is_split) {
        if (threshold < 2) {
            fprintf(stderr, "Error: threshold must be at least 2\n");
            print_usage_split(prog);
            return 1;
        }
        if (num_shares < threshold) {
            fprintf(stderr, "Error: num_shares must be >= threshold\n");
            print_usage_split(prog);
            return 1;
        }
        return do_split(threshold, num_shares);
    } else {
        if (threshold < 2) {
            fprintf(stderr, "Error: threshold must be at least 2\n");
            print_usage_combine(prog);
            return 1;
        }
        return do_combine(threshold);
    }
}
