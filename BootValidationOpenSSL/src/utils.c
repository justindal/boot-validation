#include "boot_validation.h"

int file_exists(const char* filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

int ensure_key_directory() {
    struct stat st = {0};
    if (stat(KEY_DIR_PATH, &st) == -1) {
        if (mkdir(KEY_DIR_PATH, 0700) == -1) {
            printf("directory not created: %s\n", strerror(errno));
            return -1;
        }
        printf("created key directory: %s\n", KEY_DIR_PATH);
    }
    return 0;
} 