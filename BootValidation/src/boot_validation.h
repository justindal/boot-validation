#ifndef BOOT_VALIDATION_H
#define BOOT_VALIDATION_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>

#define KERNEL_IMAGE_MAX_SIZE  0x1000000
#define DILITHIUM_SIG_SIZE     3309
#define DILITHIUM_LEVEL        WC_ML_DSA_65
#define DILITHIUM_PUB_KEY_SIZE 1952
#define DILITHIUM_PRV_KEY_SIZE 4032

#define PUBLIC_KEY_PATH  "/etc/boot_validation/dilithium_public.key"
#define PRIVATE_KEY_PATH "/etc/boot_validation/dilithium_private.key"
#define KEY_DIR_PATH     "/etc/boot_validation"
#define SIGNATURE_PATH   "/etc/boot_validation/kernel.sig"
#define KERNEL_COPY_PATH "/etc/boot_validation/kernel_copy"

int file_exists(const char* filename);
int ensure_key_directory(void);
int generate_dilithium_keys(void);
int verify_signature_with_diagnostics(const unsigned char *signature, word32 sigSize,
                                    const unsigned char *hash, size_t hashSize,
                                    const unsigned char *publicKey, size_t publicKeySize);
int sign_hash(const unsigned char *hash, size_t hashSize, 
             unsigned char *signature, word32 *sigSize);
int validate_kernel_image(void);
int test_kernel_comparison(void);
int measure_validation_metrics(void);
void print_usage(const char* progname);

#endif