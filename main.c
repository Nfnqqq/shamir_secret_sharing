#include "ssss.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>

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

    ssss_ctx_t ctx;
    ssss_ctx_init(&ctx);

    int prime_version = 0;
    if (ssss_split_ex(&ctx, secret, threshold, num_shares, 1, &prime_version) != 0) {
        fprintf(stderr, "Error splitting secret\n");
        ssss_ctx_clear(&ctx);
        return 1;
    }

    for (int i = 0; i < num_shares; i++) {
        print_paper_share_ex(i + 1, num_shares, threshold, &ctx.shares[i], prime_version, ctx.is_bip39, ctx.bip39_words);
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

    /* Ask for mode: BIP39 word count or version */
    printf("Mode (B12/B15/B18/B21/B24 for BIP39, or V1/V2/V3/V4 for text): ");
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
        mpz_init(shares[i].value);
        if (mpz_set_str(shares[i].value, line, 10) != 0) {
            fprintf(stderr, "Error parsing value\n");
            mpz_clear(shares[i].value);
            goto error;
        }
        share_count++;
    }

    char secret[MAX_SECRET_LEN + 1];
    if (ssss_combine_bip39(secret, sizeof(secret), shares, threshold, prime, bip39_words) != 0) {
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
