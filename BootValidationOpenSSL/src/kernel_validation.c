#include "boot_validation.h"

int validate_kernel_image(void) {
    printf("Starting QNX kernel image validation...\n");
    int status = EXIT_FAILURE;
    int ret;
    unsigned char *kernel_data = NULL;
    unsigned char hash[SHA256_DIGEST_LENGTH];
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
            printf("failed to allocate memory for kernel copy\n");
            fclose(src);
            return EXIT_FAILURE;
        }

        if (fread(kernel_data, 1, size, src) != size) {
            printf("failed to read kernel file for copying\n");
            fclose(src);
            free(kernel_data);
            return EXIT_FAILURE;
        }
        fclose(src);

        FILE *dst = fopen(KERNEL_COPY_PATH, "wb");
        if (!dst) {
            printf("failed to create kernel copy: %s\n", strerror(errno));
            free(kernel_data);
            return EXIT_FAILURE;
        }

        if (fwrite(kernel_data, 1, size, dst) != size) {
            printf("failed to write kernel copy\n");
            fclose(dst);
            free(kernel_data);
            return EXIT_FAILURE;
        }
        fclose(dst);

        printf("Kernel copy created successfully\n");

        // calculate hash of the original kernel
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, kernel_data, size);
        SHA256_Final(hash, &sha256);

        printf("Original kernel hash: ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");

        // sign hash
        unsigned char signature[RSA_SIG_SIZE];
        size_t sigSize = RSA_SIG_SIZE;

        ret = sign_hash(hash, SHA256_DIGEST_LENGTH, signature, &sigSize);
        if (ret != 0) {
            printf("failed to sign kernel hash\n");
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

    // calculate hash
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, kernel_data, st.st_size);
    SHA256_Final(hash, &sha256);

    printf("Kernel copy hash: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
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

    unsigned char signature[RSA_SIG_SIZE];
    size_t sig_size = fread(signature, 1, RSA_SIG_SIZE, sig_file);
    fclose(sig_file);

    if (sig_size != RSA_SIG_SIZE) {
        printf("invalid signature size: %zu bytes (expected %d)\n",
               sig_size, RSA_SIG_SIZE);
        free(kernel_data);
        return EXIT_FAILURE;
    }

    printf("\nVerifying Signature...\n");

    // verify using public key
    ret = verify_signature(signature, sig_size, hash, SHA256_DIGEST_LENGTH, NULL, 0);

    if (ret == 1) {
        printf("Signature verification successful!\n");
        status = EXIT_SUCCESS;
    } else {
        printf("Signature verification failed\n");
        printf("the kernel image may have been modified\n");
    }

    free(kernel_data);
    return status;
}

int measure_validation_metrics(void) {
    printf("\nMeasuring Boot Validation Metrics...\n");
    int ret;
    struct timespec start, end;
    unsigned char *kernel_data = NULL;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char signature[RSA_SIG_SIZE];
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
    printf("   RSA key size: %d bits\n", RSA_KEY_SIZE);
    printf("   RSA signature size: %d bytes\n", RSA_SIG_SIZE);

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

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, kernel_data, st.st_size);
    SHA256_Final(hash, &sha256);

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

        size_t sig_size = fread(signature, 1, RSA_SIG_SIZE, sig_file);
        fclose(sig_file);

        if (sig_size != RSA_SIG_SIZE) {
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

        RSA *rsa = PEM_read_RSAPublicKey(pub_file, NULL, NULL, NULL);
        fclose(pub_file);

        if (!rsa) {
            printf("failed to read public key\n");
            free(kernel_data);
            return -1;
        }

        clock_gettime(CLOCK_MONOTONIC, &start);
        ret = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
                        signature, RSA_SIG_SIZE, rsa);
        clock_gettime(CLOCK_MONOTONIC, &end);

        double verify_time = (end.tv_sec - start.tv_sec) + 
                           (end.tv_nsec - start.tv_nsec) / 1e9;

        printf("   RSA signature verification time: %.6f seconds\n", verify_time);
        RSA_free(rsa);
    }

    printf("\n4. Memory Usage:\n");
    printf("   Kernel buffer: %zu bytes\n", st.st_size);
    printf("   Total buffers: %zu bytes\n",
           st.st_size + RSA_SIG_SIZE);

    free(kernel_data);
    return 0;
} 