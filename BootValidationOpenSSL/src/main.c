#include "boot_validation.h"

void print_usage(const char* progname) {
    printf("QNX Classical Boot Validation using RSA\n");
    printf("Usage:\n");
    printf("  %s                       - Validate QNX kernel image\n", progname);
    printf("  %s generate-keys         - Generate new RSA key pair\n", progname);
    printf("  %s measure-metrics       - Measure validation metrics\n", progname);
    printf("  %s --help                - Show this help message\n", progname);
    printf("\n");
    printf("Security level: RSA-2048 with SHA-256\n");
}

int main(int argc, char** argv) {
    int ret;
    struct timespec start_time, end_time;
    double total_time;

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if (argc > 1) {
        if (strcmp(argv[1], "generate-keys") == 0) {
            ret = generate_rsa_keys();
            EVP_cleanup();
            // End timing
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            total_time = (end_time.tv_sec - start_time.tv_sec) + 
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("\nTotal execution time: %.6f seconds\n", total_time);
            return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
        }
        else if (strcmp(argv[1], "measure-metrics") == 0) {
            ret = measure_validation_metrics();
            EVP_cleanup();

            clock_gettime(CLOCK_MONOTONIC, &end_time);
            total_time = (end_time.tv_sec - start_time.tv_sec) + 
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("\nTotal execution time: %.6f seconds\n", total_time);
            return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
        }
        else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_usage(argv[0]);
            EVP_cleanup();

            clock_gettime(CLOCK_MONOTONIC, &end_time);
            total_time = (end_time.tv_sec - start_time.tv_sec) + 
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("\nTotal execution time: %.6f seconds\n", total_time);
            return EXIT_SUCCESS;
        }
        else {
            printf("Unknown command: %s\n", argv[1]);
            print_usage(argv[0]);
            EVP_cleanup();

            clock_gettime(CLOCK_MONOTONIC, &end_time);
            total_time = (end_time.tv_sec - start_time.tv_sec) + 
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("\nTotal execution time: %.6f seconds\n", total_time);
            return EXIT_FAILURE;
        }
    }

    printf("Validating Boot...\n");

    if (ensure_key_directory() != 0) {
        EVP_cleanup();
        // End timing
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_time = (end_time.tv_sec - start_time.tv_sec) + 
                    (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
        printf("\nTotal execution time: %.6f seconds\n", total_time);
        return EXIT_FAILURE;
    }

    if (!file_exists(PUBLIC_KEY_PATH) || !file_exists(PRIVATE_KEY_PATH)) {
        printf("keys not found, generating...\n");
        ret = generate_rsa_keys();
        if (ret != 0) {
            printf("failed to generate keys, aborting...\n");
            EVP_cleanup();
            // End timing
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            total_time = (end_time.tv_sec - start_time.tv_sec) + 
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("\nTotal execution time: %.6f seconds\n", total_time);
            return EXIT_FAILURE;
        }
        printf("Keys generated successfully\n");
    }

    ret = validate_kernel_image();

    EVP_cleanup();

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    total_time = (end_time.tv_sec - start_time.tv_sec) + 
                (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    printf("\nTotal execution time: %.6f seconds\n", total_time);

    if (ret == EXIT_SUCCESS) {
        printf("Kernel image validation passed, boot can continue\n");
        return EXIT_SUCCESS;
    } else {
        printf("Kernel image validation failed, boot must stop\n");
        return EXIT_FAILURE;
    }
} 