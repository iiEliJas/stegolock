#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stegolock.h"

void print_usage(const char *program_name) {
    printf("Stegolock - AES-256-GCM Password Vault Steganography Tool\n\n");
    printf("Usage:\n");
    printf("  %s init <image.bmp>\n", program_name);
    printf("    Initialize a new password vault in a BMP image\n\n");
    printf("  %s add <image.bmp> <website>\n", program_name);
    printf("    Add a password entry for a website\n\n");
    printf("  %s get <image.bmp> <website>\n", program_name);
    printf("    Retrieve a password entry for a website\n\n");
    printf("  %s list <image.bmp>\n", program_name);
    printf("    List all websites in the vault\n\n");
    printf("  %s del <image.bmp> <website>\n", program_name);
    printf("    Delete a password entry for a website\n\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *command = argv[1];
    
    if (strcmp(command, "init") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Error: init requires an image path\n");
            return 1;
        }
        return stegolock_init(argv[2]);
    }
    else if (strcmp(command, "add") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: add requires image path and website\n");
            return 1;
        }
        return stegolock_add(argv[2], argv[3]);
    }
    else if (strcmp(command, "get") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: get requires image path and website\n");
            return 1;
        }
        return stegolock_get(argv[2], argv[3]);
    }
    else if (strcmp(command, "list") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Error: list requires an image path\n");
            return 1;
        }
        return stegolock_list(argv[2]);
    }
    else if (strcmp(command, "del") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: del requires image path and website\n");
            return 1;
        }
        return stegolock_del(argv[2], argv[3]);
    }
    else if (strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    }
    else {
        fprintf(stderr, "Error: Unknown command '%s'\n\n", command);
        print_usage(argv[0]);
        return 1;
    }
}
