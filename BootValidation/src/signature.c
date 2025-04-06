#include "boot_validation.h"

int verify_signature_with_diagnostics(const unsigned char *signature, word32 sigSize,
                                    const unsigned char *hash, size_t hashSize,
                                    const unsigned char *publicKey, size_t publicKeySize) {
    int ret;
    dilithium_key key;
    int verify_result = 0;
    
    ret = wc_dilithium_init(&key);
    if (ret != 0) {
        printf("could not initialize dilithium key: %d\n", ret);
        return ret;
    }
    
    ret = wc_dilithium_set_level(&key, DILITHIUM_LEVEL);
    if (ret != 0) {
        printf("could not set key level: %d\n", ret);
        wc_dilithium_free(&key);
        return ret;
    }
    
    ret = wc_dilithium_import_public(publicKey, publicKeySize, &key);
    if (ret != 0) {
        printf("could not import public key: %d\n", ret);
        wc_dilithium_free(&key);
        return ret;
    }

    printf("\nSignature Verification Debug:\n");
    printf("signature size: %d bytes\n", sigSize);
    printf("hash size: %zu bytes\n", hashSize);
    printf("public key size: %zu bytes\n", publicKeySize);
    
    printf("First 16 bytes of signature: ");
    for (int i = 0; i < 16 && i < sigSize; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");
    
    printf("First 16 bytes of hash: ");
    for (int i = 0; i < 16 && i < hashSize; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    printf("First 16 bytes of public key: ");
    for (int i = 0; i < 16 && i < publicKeySize; i++) {
        printf("%02x", publicKey[i]);
    }
    printf("\n");
    
    ret = wc_dilithium_verify_msg(signature, sigSize, hash, hashSize, &verify_result, &key);
    wc_dilithium_free(&key);
    
    if (ret != 0) {
        printf("error verifying signature: %d\n", ret);
        return ret;
    }
    
    return verify_result;
}

int sign_hash(const unsigned char *hash, size_t hashSize, 
             unsigned char *signature, word32 *sigSize) {
    int ret;
    FILE *privFile;
    dilithium_key key;
    unsigned char privateKey[DILITHIUM_PRV_KEY_SIZE];
    size_t bytesRead;
    WC_RNG rng;
    
    // check and load private key
    if (!file_exists(PRIVATE_KEY_PATH)) {
        printf("Private key file not found: %s\n", PRIVATE_KEY_PATH);
        return -1;
    }

    privFile = fopen(PRIVATE_KEY_PATH, "rb");
    if (privFile == NULL) {
        printf("Failed to open private key file: %s\n", strerror(errno));
        return -1;
    }
    
    bytesRead = fread(privateKey, 1, DILITHIUM_PRV_KEY_SIZE, privFile);
    fclose(privFile);
    
    if (bytesRead != DILITHIUM_PRV_KEY_SIZE) {
        printf("Failed to read complete private key. Read %zu bytes, expected %d\n",
               bytesRead, DILITHIUM_PRV_KEY_SIZE);
        return -1;
    }
    
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("Failed to initialize RNG: %d\n", ret);
        return ret;
    }
    
    ret = wc_dilithium_init(&key);
    if (ret != 0) {
        printf("Failed to initialize Dilithium key: %d\n", ret);
        wc_FreeRng(&rng);
        return ret;
    }
    
    // set key level to 3
    ret = wc_dilithium_set_level(&key, DILITHIUM_LEVEL);
    if (ret != 0) {
        printf("Failed to set Dilithium key level: %d\n", ret);
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return ret;
    }
    
    // private key
    ret = wc_dilithium_import_private(privateKey, DILITHIUM_PRV_KEY_SIZE, &key);
    if (ret != 0) {
        printf("Failed to import private key: %d\n", ret);
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return ret;
    }
    
    ret = wc_dilithium_sign_msg(hash, hashSize, signature, sigSize, &key, &rng);
    
    wc_dilithium_free(&key);
    wc_FreeRng(&rng);
    
    if (ret != 0) {
        printf("Failed to sign hash: %d\n", ret);
        return ret;
    }
    
    printf("Hash signed successfully\n");
    return 0;
} 