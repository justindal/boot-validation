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

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#define KERNEL_IMAGE_MAX_SIZE  0x1000000
#define RSA_KEY_SIZE          2048
#define RSA_SIG_SIZE         256

#define PUBLIC_KEY_PATH  "/etc/boot_validation/rsa_public.key"
#define PRIVATE_KEY_PATH "/etc/boot_validation/rsa_private.key"
#define KEY_DIR_PATH     "/etc/boot_validation"
#define SIGNATURE_PATH   "/etc/boot_validation/kernel.sig"
#define KERNEL_COPY_PATH "/etc/boot_validation/kernel_copy"

int file_exists(const char* filename);
int ensure_key_directory(void);

int generate_rsa_keys(void);

int sign_hash(const unsigned char *hash, size_t hashSize,
             unsigned char *signature, size_t *sigSize);
int verify_signature(const unsigned char *signature, size_t sigSize,
                    const unsigned char *hash, size_t hashSize,
                    const unsigned char *publicKey, size_t publicKeySize);

int validate_kernel_image(void);
int measure_validation_metrics(void);

void print_usage(const char* progname);

#endif