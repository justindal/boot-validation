#include "boot_validation.h"

int sign_hash(const unsigned char *hash, size_t hashSize,
             unsigned char *signature, size_t *sigSize) {
    FILE *privFile;
    RSA *rsa = NULL;
    int ret;

    privFile = fopen(PRIVATE_KEY_PATH, "rb");
    if (!privFile) {
        printf("failed to open private key file: %s\n", strerror(errno));
        return -1;
    }

    rsa = PEM_read_RSAPrivateKey(privFile, NULL, NULL, NULL);
    fclose(privFile);

    if (!rsa) {
        printf("failed to read private key\n");
        return -1;
    }

    ret = RSA_sign(NID_sha256, hash, hashSize, signature, (unsigned int*)sigSize, rsa);
    RSA_free(rsa);

    if (ret != 1) {
        printf("failed to sign hash\n");
        return -1;
    }

    printf("Hash signed successfully\n");
    return 0;
}

int verify_signature(const unsigned char *signature, size_t sigSize,
                    const unsigned char *hash, size_t hashSize,
                    const unsigned char *publicKey, size_t publicKeySize) {
    RSA *rsa = NULL;
    int ret;

    FILE *pubFile = fopen(PUBLIC_KEY_PATH, "rb");
    if (!pubFile) {
        printf("failed to open public key file: %s\n", strerror(errno));
        return -1;
    }

    rsa = PEM_read_RSAPublicKey(pubFile, NULL, NULL, NULL);
    fclose(pubFile);

    if (!rsa) {
        printf("failed to read public key\n");
        return -1;
    }

    ret = RSA_verify(NID_sha256, hash, hashSize, signature, sigSize, rsa);
    RSA_free(rsa);

    if (ret != 1) {
        printf("signature verification failed\n");
        return 0;
    }

    printf("signature verification successful\n");
    return 1;
} 