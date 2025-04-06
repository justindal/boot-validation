#include "boot_validation.h"

void print_usage(const char* progname) {
    printf("QNX Post-Quantum Boot Validation using Dilithium\n");
    printf("Usage:\n");
    printf("  %s                       - Validate QNX kernel image\n", progname);
    printf("  %s generate-keys         - Generate new Dilithium key pair\n", progname);
    printf("  %s test-comparison       - Test kernel memory vs saved copy\n", progname);
    printf("  %s measure-metrics       - Measure validation metrics\n", progname);
    printf("  %s --help                - Show this help message\n", progname);
    printf("\n");
    printf("Security level: Dilithium Level 3 (NIST PQC standard)\n");
}

int main(int argc, char** argv) {
    int ret;
    struct timespec start_time, end_time;
    double total_time;

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        printf("Failed to initialize wolfSSL: %d\n", ret);
        return EXIT_FAILURE;
    }

    if (argc > 1) {
        if (strcmp(argv[1], "generate-keys") == 0) {
            ret = generate_dilithium_keys();
            wolfSSL_Cleanup();

            clock_gettime(CLOCK_MONOTONIC, &end_time);
            total_time = (end_time.tv_sec - start_time.tv_sec) + 
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("\nTotal execution time: %.6f seconds\n", total_time);
            return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
        }
        else if (strcmp(argv[1], "test-comparison") == 0) {
            ret = test_kernel_comparison();
            wolfSSL_Cleanup();
            
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            total_time = (end_time.tv_sec - start_time.tv_sec) + 
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("\nTotal execution time: %.6f seconds\n", total_time);
            return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
        }
        else if (strcmp(argv[1], "measure-metrics") == 0) {
            ret = measure_validation_metrics();
            wolfSSL_Cleanup();
            
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            total_time = (end_time.tv_sec - start_time.tv_sec) + 
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("\nTotal execution time: %.6f seconds\n", total_time);
            return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
        }
        else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_usage(argv[0]);
            wolfSSL_Cleanup();
            
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            total_time = (end_time.tv_sec - start_time.tv_sec) + 
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("\nTotal execution time: %.6f seconds\n", total_time);
            return EXIT_SUCCESS;
        }
        else {
            printf("Unknown command: %s\n", argv[1]);
            print_usage(argv[0]);
            wolfSSL_Cleanup();
            
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            total_time = (end_time.tv_sec - start_time.tv_sec) + 
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("\nTotal execution time: %.6f seconds\n", total_time);
            return EXIT_FAILURE;
        }
    }
    
    printf("Validating Boot...\n");
    
    if (ensure_key_directory() != 0) {
        wolfSSL_Cleanup();
        
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_time = (end_time.tv_sec - start_time.tv_sec) + 
                    (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
        printf("\nTotal execution time: %.6f seconds\n", total_time);
        return EXIT_FAILURE;
    }
    
    if (!file_exists(PUBLIC_KEY_PATH) || !file_exists(PRIVATE_KEY_PATH)) {
        printf("keys not found, generating...\n");
        ret = generate_dilithium_keys();
        if (ret != 0) {
            printf("failed to generate keys, aborting...\n");
            wolfSSL_Cleanup();
            
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            total_time = (end_time.tv_sec - start_time.tv_sec) + 
                        (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("\nTotal execution time: %.6f seconds\n", total_time);
            return EXIT_FAILURE;
        }
        printf("Keys generated successfully\n");
    }
    
    ret = validate_kernel_image();
    
    wolfSSL_Cleanup();
    
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