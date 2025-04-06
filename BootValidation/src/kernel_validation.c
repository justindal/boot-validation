#include "boot_validation.h"

int validate_kernel_image(void) {
    printf("Starting QNX kernel image validation...\n");
    int status = EXIT_FAILURE;
    int ret;
    unsigned char *kernel_data = NULL;
    unsigned char hash[SHA256_DIGEST_SIZE];
    unsigned char public_key[DILITHIUM_PUB_KEY_SIZE];
    struct stat st;
    const char *kernel_path = "/proc/boot/procnto-smp-instr";
    
    // if saved kernel copy does not yet exist, do so
    if (!file_exists(KERNEL_COPY_PATH)) {
        printf("creating copy...\n");
        
        FILE *src = fopen(kernel_path, "rb");
        if (!src) {
            printf("failed to open kernel file for copying: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
        
        fseek(src, 0, SEEK_END);
        size_t size = ftell(src);
        fseek(src, 0, SEEK_SET);
        
        kernel_data = (unsigned char*)malloc(size);
        if (!kernel_data) {
            printf("Failed to allocate memory for kernel copy\n");
            fclose(src);
            return EXIT_FAILURE;
        }
        
        if (fread(kernel_data, 1, size, src) != size) {
            printf("Failed to read kernel file for copying\n");
            fclose(src);
            free(kernel_data);
            return EXIT_FAILURE;
        }
        fclose(src);
        
        FILE *dst = fopen(KERNEL_COPY_PATH, "wb");
        if (!dst) {
            printf("Failed to create kernel copy: %s\n", strerror(errno));
            free(kernel_data);
            return EXIT_FAILURE;
        }
        
        if (fwrite(kernel_data, 1, size, dst) != size) {
            printf("Failed to write kernel copy\n");
            fclose(dst);
            free(kernel_data);
            return EXIT_FAILURE;
        }
        fclose(dst);
        
        printf("Kernel copy created successfully\n");
        
        // find hash of the original kernel
        Sha256 sha;
        ret = wc_InitSha256(&sha);
        if (ret != 0) {
            printf("Failed to initialize SHA-256: %d\n", ret);
            free(kernel_data);
            return EXIT_FAILURE;
        }
        
        ret = wc_Sha256Update(&sha, kernel_data, size);
        if (ret != 0) {
            printf("Failed to update SHA-256: %d\n", ret);
            wc_Sha256Free(&sha);
            free(kernel_data);
            return EXIT_FAILURE;
        }
        
        ret = wc_Sha256Final(&sha, hash);
        wc_Sha256Free(&sha);
        if (ret != 0) {
            printf("Failed to finalize SHA-256: %d\n", ret);
            free(kernel_data);
            return EXIT_FAILURE;
        }
        
        printf("Original kernel hash: ");
        for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
        
        // sign hashes
        unsigned char signature[DILITHIUM_SIG_SIZE];
        word32 sigSize = DILITHIUM_SIG_SIZE;
        
        ret = sign_hash(hash, SHA256_DIGEST_SIZE, signature, &sigSize);
        if (ret != 0) {
            printf("Failed to sign kernel hash\n");
            free(kernel_data);
            return EXIT_FAILURE;
        }
        
        // save the signature
        FILE *sigFile = fopen(SIGNATURE_PATH, "wb");
        if (!sigFile) {
            printf("failed to create signature file: %s\n", strerror(errno));
            free(kernel_data);
            return -1;
        }
        
        if (fwrite(signature, 1, sigSize, sigFile) != sigSize) {
            printf("failed to write signature: %s\n", strerror(errno));
            fclose(sigFile);
            free(kernel_data);
            return -1;
        }
        fclose(sigFile);
        
        printf("Kernel image signed successfully\n");
        printf("signature saved to %s\n", SIGNATURE_PATH);
        free(kernel_data);
        return EXIT_SUCCESS;
    }
    
    printf("Validating against saved kernel copy...\n");
    
    if (stat(KERNEL_COPY_PATH, &st) != 0) {
        printf("unable to get kernel copy info: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    
    // verify kernel size
    if (st.st_size > KERNEL_IMAGE_MAX_SIZE) {
        printf("Error: Kernel size (%zu) exceeds maximum allowed size (%d)\n",
               st.st_size, KERNEL_IMAGE_MAX_SIZE);
        return EXIT_FAILURE;
    }
    
    printf("Kernel copy size: %zu bytes (0x%zx)\n", st.st_size, st.st_size);
    
    kernel_data = (unsigned char*)malloc(st.st_size);
    if (!kernel_data) {
        printf("failed to allocate memory for kernel data\n");
        return EXIT_FAILURE;
    }

    printf("Reading kernel copy...\n");
    FILE *copyFile = fopen(KERNEL_COPY_PATH, "rb");
    if (!copyFile) {
        printf("failed to open kernel copy: %s\n", strerror(errno));
        free(kernel_data);
        return EXIT_FAILURE;
    }
    
    if (fread(kernel_data, 1, st.st_size, copyFile) != st.st_size) {
        printf("failed to read kernel copy\n");
        fclose(copyFile);
        free(kernel_data);
        return EXIT_FAILURE;
    }
    fclose(copyFile);
    
    // calculate hashes
    Sha256 sha;
    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        printf("Failed to initialize SHA-256: %d\n", ret);
        free(kernel_data);
        return EXIT_FAILURE;
    }
    
    ret = wc_Sha256Update(&sha, kernel_data, st.st_size);
    if (ret != 0) {
        printf("Failed to update SHA-256: %d\n", ret);
        wc_Sha256Free(&sha);
        free(kernel_data);
        return EXIT_FAILURE;
    }
    
    ret = wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);
    if (ret != 0) {
        printf("failed to finalize SHA-256: %d\n", ret);
        free(kernel_data);
        return EXIT_FAILURE;
    }
    
    printf("Kernel copy hash: ");
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    // read signature
    FILE *sig_file = fopen(SIGNATURE_PATH, "rb");
    if (!sig_file) {
        printf("could not open signature file\n");
        free(kernel_data);
        return EXIT_FAILURE;
    }
    
    unsigned char signature[DILITHIUM_SIG_SIZE];
    size_t sig_size = fread(signature, 1, DILITHIUM_SIG_SIZE, sig_file);
    fclose(sig_file);
    
    if (sig_size != DILITHIUM_SIG_SIZE) {
        printf("invalid size: %zu bytes (expected %d)\n",
               sig_size, DILITHIUM_SIG_SIZE);
        free(kernel_data);
        return EXIT_FAILURE;
    }
    
    FILE *pub_file = fopen(PUBLIC_KEY_PATH, "rb");
    if (!pub_file) {
        printf("Failed to open public key file for verification\n");
        free(kernel_data);
        return EXIT_FAILURE;
    }
    
    size_t pub_size = fread(public_key, 1, DILITHIUM_PUB_KEY_SIZE, pub_file);
    fclose(pub_file);
    
    if (pub_size != DILITHIUM_PUB_KEY_SIZE) {
        printf("failed to read complete public key for verification\n");
        free(kernel_data);
        return EXIT_FAILURE;
    }
    
    printf("\nVerifying Signature...\n");
    
    // verify using public key
    ret = verify_signature_with_diagnostics(signature, DILITHIUM_SIG_SIZE,
                                          hash, SHA256_DIGEST_SIZE,
                                          public_key, DILITHIUM_PUB_KEY_SIZE);
    
    if (ret == 1) {
        printf("Signature verification successful!\n");
        status = EXIT_SUCCESS;
    } else if (ret == 0) {
        printf("Signature verification failed\n");
        printf("the kernel image may have been modified\n");
    } else {
        printf("Error during signature verification: %d\n", ret);
    }
    
    free(kernel_data);
    return status;
}

int test_kernel_comparison(void) {
    printf("\nTesting kernel memory vs saved copy...\n");
    int ret;
    unsigned char *memory_kernel = NULL;
    unsigned char *saved_kernel = NULL;
    unsigned char memory_hash[SHA256_DIGEST_SIZE];
    unsigned char saved_hash[SHA256_DIGEST_SIZE];
    struct stat st;
    const char *kernel_path = "/proc/boot/procnto-smp-instr";

    FILE *mem_file = fopen(kernel_path, "rb");
    if (!mem_file) {
        printf("could not open running kernel: %s\n", strerror(errno));
        return -1;
    }

    fseek(mem_file, 0, SEEK_END);
    size_t mem_size = ftell(mem_file);
    fseek(mem_file, 0, SEEK_SET);

    memory_kernel = (unsigned char*)malloc(mem_size);
    if (!memory_kernel) {
        printf("failed to allocate memory for running kernel\n");
        fclose(mem_file);
        return -1;
    }
    
    if (fread(memory_kernel, 1, mem_size, mem_file) != mem_size) {
        printf("failed to read running kernel\n");
        fclose(mem_file);
        free(memory_kernel);
        return -1;
    }
    fclose(mem_file);
    
    Sha256 sha;
    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        printf("failed to initialize SHA-256: %d\n", ret);
        free(memory_kernel);
        return -1;
    }
    
    ret = wc_Sha256Update(&sha, memory_kernel, mem_size);
    if (ret != 0) {
        printf("failed to update SHA-256: %d\n", ret);
        wc_Sha256Free(&sha);
        free(memory_kernel);
        return -1;
    }
    
    ret = wc_Sha256Final(&sha, memory_hash);
    wc_Sha256Free(&sha);
    if (ret != 0) {
        printf("failed to finalize SHA-256: %d\n", ret);
        free(memory_kernel);
        return -1;
    }
    
    printf("memory kernel hash: ");
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        printf("%02x", memory_hash[i]);
    }
    printf("\n");
    
    if (stat(KERNEL_COPY_PATH, &st) != 0) {
        printf("failed to get saved kernel info: %s\n", strerror(errno));
        free(memory_kernel);
        return -1;
    }

    saved_kernel = (unsigned char*)malloc(st.st_size);
    if (!saved_kernel) {
        printf("failed to allocate memory for saved kernel\n");
        free(memory_kernel);
        return -1;
    }

    FILE *saved_file = fopen(KERNEL_COPY_PATH, "rb");
    if (!saved_file) {
        printf("failed to open saved kernel: %s\n", strerror(errno));
        free(memory_kernel);
        free(saved_kernel);
        return -1;
    }
    
    if (fread(saved_kernel, 1, st.st_size, saved_file) != st.st_size) {
        printf("failed to read saved kernel\n");
        fclose(saved_file);
        free(memory_kernel);
        free(saved_kernel);
        return -1;
    }
    fclose(saved_file);
    
    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        printf("failed to initialize SHA-256: %d\n", ret);
        free(memory_kernel);
        free(saved_kernel);
        return -1;
    }
    
    ret = wc_Sha256Update(&sha, saved_kernel, st.st_size);
    if (ret != 0) {
        printf("failed to update SHA-256: %d\n", ret);
        wc_Sha256Free(&sha);
        free(memory_kernel);
        free(saved_kernel);
        return -1;
    }
    
    ret = wc_Sha256Final(&sha, saved_hash);
    wc_Sha256Free(&sha);
    if (ret != 0) {
        printf("failed to finalize SHA-256: %d\n", ret);
        free(memory_kernel);
        free(saved_kernel);
        return -1;
    }
    
    printf("saved kernel hash: ");
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        printf("%02x", saved_hash[i]);
    }
    printf("\n");

    printf("\nSize comparison:\n");
    printf("Running kernel: %zu bytes\n", mem_size);
    printf("Saved kernel: %zu bytes\n", st.st_size);
    
    printf("\nHash comparison:\n");
    if (memcmp(memory_hash, saved_hash, SHA256_DIGEST_SIZE) == 0) {
        printf("Hashes match, oops this should not happen!\n");
    } else {
        printf("Hashes differ!\n");
        printf("running kernel will always have a different hash and signature.\n");
    }
    

    size_t min_size = (mem_size < st.st_size) ? mem_size : st.st_size;
    size_t first_diff = 0;
    while (first_diff < min_size && memory_kernel[first_diff] == saved_kernel[first_diff]) {
        first_diff++;
    }
    
    free(memory_kernel);
    free(saved_kernel);
    return 0;
}

int measure_validation_metrics(void) {
    printf("\nMeasuring Boot Validation Metrics...\n");
    int ret;
    struct timespec start, end;
    unsigned char *kernel_data = NULL;
    unsigned char hash[SHA256_DIGEST_SIZE];
    unsigned char signature[DILITHIUM_SIG_SIZE];
    struct stat st;
    const char *kernel_path = "/proc/boot/procnto-smp-instr";

    if (stat(kernel_path, &st) != 0) {
        printf("failed to get kernel info: %s\n", strerror(errno));
        return -1;
    }
    printf("\n1. Kernel Size Metrics:\n");
    printf("   Kernel file size: %zu bytes (%.2f MB)\n", 
           st.st_size, (double)st.st_size / (1024 * 1024));

    printf("\n2. Key and Signature Sizes:\n");
    printf("   Public key size: %d bytes\n", DILITHIUM_PUB_KEY_SIZE);
    printf("   Private key size: %d bytes\n", DILITHIUM_PRV_KEY_SIZE);
    printf("   Signature size: %d bytes\n", DILITHIUM_SIG_SIZE);

    clock_gettime(CLOCK_MONOTONIC, &start);
    
    kernel_data = (unsigned char*)malloc(st.st_size);
    if (!kernel_data) {
        printf("failed to allocate memory for kernel data\n");
        return -1;
    }
    
    FILE *kernel_file = fopen(kernel_path, "rb");
    if (!kernel_file) {
        printf("failed to open kernel file: %s\n", strerror(errno));
        free(kernel_data);
        return -1;
    }
    
    if (fread(kernel_data, 1, st.st_size, kernel_file) != st.st_size) {
        printf("failed to read kernel file\n");
        fclose(kernel_file);
        free(kernel_data);
        return -1;
    }
    fclose(kernel_file);
    
    Sha256 sha;
    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        printf("failed to initialize SHA-256: %d\n", ret);
        free(kernel_data);
        return -1;
    }
    
    ret = wc_Sha256Update(&sha, kernel_data, st.st_size);
    if (ret != 0) {
        printf("failed to update SHA-256: %d\n", ret);
        wc_Sha256Free(&sha);
        free(kernel_data);
        return -1;
    }
    
    ret = wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);
    if (ret != 0) {
        printf("failed to finalize SHA-256: %d\n", ret);
        free(kernel_data);
        return -1;
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    double hash_time = (end.tv_sec - start.tv_sec) + 
                      (end.tv_nsec - start.tv_nsec) / 1e9;
    
    printf("\n3. Performance Metrics:\n");
    printf("   SHA-256 hash calculation time: %.6f seconds\n", hash_time);
    printf("   Hash calculation speed: %.2f MB/s\n", 
           (st.st_size / (1024 * 1024)) / hash_time);

    if (file_exists(SIGNATURE_PATH)) {
        FILE *sig_file = fopen(SIGNATURE_PATH, "rb");
        if (!sig_file) {
            printf("failed to open signature file: %s\n", strerror(errno));
            free(kernel_data);
            return -1;
        }
        
        size_t sig_size = fread(signature, 1, DILITHIUM_SIG_SIZE, sig_file);
        fclose(sig_file);
        
        if (sig_size != DILITHIUM_SIG_SIZE) {
            printf("invalid signature size: %zu bytes\n", sig_size);
            free(kernel_data);
            return -1;
        }
        
        FILE *pub_file = fopen(PUBLIC_KEY_PATH, "rb");
        if (!pub_file) {
            printf("failed to open public key file\n");
            free(kernel_data);
            return -1;
        }
        
        unsigned char public_key[DILITHIUM_PUB_KEY_SIZE];
        size_t pub_size = fread(public_key, 1, DILITHIUM_PUB_KEY_SIZE, pub_file);
        fclose(pub_file);
        
        if (pub_size != DILITHIUM_PUB_KEY_SIZE) {
            printf("invalid public key size: %zu bytes\n", pub_size);
            free(kernel_data);
            return -1;
        }
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        ret = verify_signature_with_diagnostics(signature, DILITHIUM_SIG_SIZE,
                                             hash, SHA256_DIGEST_SIZE,
                                             public_key, DILITHIUM_PUB_KEY_SIZE);
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        double verify_time = (end.tv_sec - start.tv_sec) + 
                           (end.tv_nsec - start.tv_nsec) / 1e9;
        
        printf("   Signature verification time: %.6f seconds\n", verify_time);
    }

    printf("\n4. Memory Usage:\n");
    printf("   Kernel buffer: %zu bytes\n", st.st_size);
    printf("   Total buffers: %zu bytes\n", 
           st.st_size + DILITHIUM_PUB_KEY_SIZE + DILITHIUM_SIG_SIZE);
    
    free(kernel_data);
    return 0;
} 