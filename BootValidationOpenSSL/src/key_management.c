#include "boot_validation.h"

int generate_rsa_keys() {
    printf("Generating new RSA key pair...\n");

    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    FILE *pubFile, *privFile;

    if (!rsa || !e) {
        printf("failed to allocate RSA key\n");
        RSA_free(rsa);
        BN_free(e);
        return -1;
    }

    if (ensure_key_directory() != 0) {
        RSA_free(rsa);
        BN_free(e);
        return -1;
    }

    BN_set_word(e, RSA_F4);

    if (RSA_generate_key_ex(rsa, RSA_KEY_SIZE, e, NULL) != 1) {
        printf("failed to generate RSA key\n");
        RSA_free(rsa);
        BN_free(e);
        return -1;
    }

    pubFile = fopen(PUBLIC_KEY_PATH, "wb");
    if (!pubFile) {
        printf("failed to create public key file: %s\n", strerror(errno));
        RSA_free(rsa);
        BN_free(e);
        return -1;
    }

    if (PEM_write_RSAPublicKey(pubFile, rsa) != 1) {
        printf("failed to write public key\n");
        fclose(pubFile);
        RSA_free(rsa);
        BN_free(e);
        return -1;
    }
    fclose(pubFile);

    privFile = fopen(PRIVATE_KEY_PATH, "wb");
    if (!privFile) {
        printf("failed to create private key file: %s\n", strerror(errno));
        RSA_free(rsa);
        BN_free(e);
        return -1;
    }

    if (PEM_write_RSAPrivateKey(privFile, rsa, NULL, NULL, 0, NULL, NULL) != 1) {
        printf("failed to write private key\n");
        fclose(privFile);
        RSA_free(rsa);
        BN_free(e);
        return -1;
    }
    fclose(privFile);

    printf("RSA key pair generated and saved successfully\n");
    printf("public key saved to: %s\n", PUBLIC_KEY_PATH);
    printf("private key saved to: %s\n", PRIVATE_KEY_PATH);

    RSA_free(rsa);
    BN_free(e);
    return 0;
} 