#include "boot_validation.h"

int generate_dilithium_keys() {
    int ret;
    WC_RNG rng;
    dilithium_key key;
    unsigned char pub[DILITHIUM_PUB_KEY_SIZE];
    unsigned char priv[DILITHIUM_PRV_KEY_SIZE];
    word32 pubSz = DILITHIUM_PUB_KEY_SIZE;
    word32 privSz = DILITHIUM_PRV_KEY_SIZE;
    FILE *pubFile, *privFile;
    
    printf("Generating new Dilithium key pair...\n");
    
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("failed initialize RNG: %d\n", ret);
        return ret;
    }
    
    ret = wc_dilithium_init(&key);
    if (ret != 0) {
        printf("failed to initialize dilithium key: %d\n", ret);
        wc_FreeRng(&rng);
        return ret;
    }

    ret = wc_dilithium_set_level(&key, DILITHIUM_LEVEL);
    if (ret != 0) {
        printf("could not set key level: %d\n", ret);
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return ret;
    }

    if (ensure_key_directory() != 0) {
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return -1;
    }

    ret = wc_dilithium_make_key(&key, &rng);
    if (ret != 0) {
        printf("error generating dilithium key: %d\n", ret);
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return ret;
    }

    ret = wc_dilithium_export_public(&key, pub, &pubSz);
    if (ret != 0) {
        printf("failed to export dilithium public key: %d\n", ret);
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return ret;
    }
    
    ret = wc_dilithium_export_private(&key, priv, &privSz);
    if (ret != 0) {
        printf("failed to export dilithium private key: %d\n", ret);
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return ret;
    }
    
    pubFile = fopen(PUBLIC_KEY_PATH, "wb");
    if (pubFile == NULL) {
        printf("save error: %s\n", strerror(errno));
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return -1;
    }
    
    if (fwrite(pub, 1, pubSz, pubFile) != pubSz) {
        printf("could not save public key: %s\n", strerror(errno));
        fclose(pubFile);
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return -1;
    }
    fclose(pubFile);
    
    privFile = fopen(PRIVATE_KEY_PATH, "wb");
    if (privFile == NULL) {
        printf("could not save public key: %s\n", strerror(errno));
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return -1;
    }
    
    if (fwrite(priv, 1, privSz, privFile) != privSz) {
        printf("could not write public key: %s\n", strerror(errno));
        fclose(privFile);
        wc_dilithium_free(&key);
        wc_FreeRng(&rng);
        return -1;
    }
    fclose(privFile);
    
    printf("Dilithium key pair generated and saved successfully\n");
    printf("public key size: %d bytes\n", pubSz);
    printf("private key size: %d bytes\n", privSz);
    printf("public key saved to: %s\n", PUBLIC_KEY_PATH);
    printf("private key saved to: %s\n", PRIVATE_KEY_PATH);
    
    wc_dilithium_free(&key);
    wc_FreeRng(&rng);
    
    return 0;
} 