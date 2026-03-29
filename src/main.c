#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "stegolock.h"

// ---------------------------------------------------------------------------
//  Enable ANSI escape codes
// ---------------------------------------------------------------------------

static void enable_ansi(void) {
    DWORD mode;
    HANDLE h;

    h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    h = GetStdHandle(STD_ERROR_HANDLE);
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

// ---------------------------------------------------------------------------
//  ANSI colors
// ---------------------------------------------------------------------------

#define CLR_RESET  "\x1b[0m"
#define CLR_BOLD   "\x1b[1m"
#define CLR_DIM    "\x1b[2m"
#define CLR_GREEN  "\x1b[32m"
#define CLR_YELLOW "\x1b[33m"
#define CLR_CYAN   "\x1b[36m"
#define CLR_WHITE  "\x1b[97m"

// ---------------------------------------------------------------------------
//  Help
// ---------------------------------------------------------------------------

static void print_usage(void) {
    printf("\n");
    printf("  " CLR_CYAN "      _                   _            _     " CLR_RESET "\n");
    printf("  " CLR_CYAN "  ___| |_ ___  __ _  ___ | | ___   ___| | __ " CLR_RESET "\n");
    printf("  " CLR_CYAN " / __| __/ _ \\/ _` |/ _ \\| |/ _ \\ / __| |/ / " CLR_RESET "\n");
    printf("  " CLR_CYAN " \\__ \\ ||  __/ (_| | (_) | | (_) | (__|   <  " CLR_RESET "\n");
    printf("  " CLR_CYAN " |___/\\__\\___|\\__, |\\___/|_|\\___/ \\___|_|\\_\\ " CLR_RESET "\n");
    printf("  " CLR_CYAN "              |___/                          " CLR_RESET "\n");

    printf("  " CLR_DIM "AES-256-GCM encrypted password vault hidden inside BMP images\n" CLR_RESET);
    printf("\n");

    printf("  " CLR_BOLD CLR_WHITE "USAGE\n" CLR_RESET);
    printf("  " CLR_DIM "---------------------------------------------\n" CLR_RESET);

    printf("  " CLR_CYAN "stegolock" CLR_RESET " " CLR_GREEN "init" CLR_RESET
        "  <image.bmp>\n");
    printf("  " CLR_DIM "          Create a new vault inside a BMP image\n\n" CLR_RESET);

    printf("  " CLR_CYAN "stegolock" CLR_RESET " " CLR_GREEN "add" CLR_RESET
        "   <image.bmp> <website>\n");
    printf("  " CLR_DIM "          Add website\n\n" CLR_RESET);

    printf("  " CLR_CYAN "stegolock" CLR_RESET " " CLR_GREEN "get" CLR_RESET
        "   <image.bmp> <website>\n");
    printf("  " CLR_DIM "          Retrieve website\n\n" CLR_RESET);

    printf("  " CLR_CYAN "stegolock" CLR_RESET " " CLR_GREEN "list" CLR_RESET
        "  <image.bmp>\n");
    printf("  " CLR_DIM "          List all websites stored in the vault\n\n" CLR_RESET);

    printf("  " CLR_CYAN "stegolock" CLR_RESET " " CLR_GREEN "del" CLR_RESET
        "   <image.bmp> <website>\n");
    printf("  " CLR_DIM "          Delete website\n\n" CLR_RESET);

    printf("  " CLR_DIM "---------------------------------------------\n" CLR_RESET);
    printf("  " CLR_YELLOW "[~] " CLR_RESET CLR_DIM
        "The previous image is always kept as image_old.bmp\n" CLR_RESET);
    printf("\n");
}

// ---------------------------------------------------------------------------
//  main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    enable_ansi();

    if (argc < 2) {
        print_usage();
        return 1;
    }

    const char* command = argv[1];

    if (strcmp(command, "init") == 0) {
        if (argc != 3) {
            fprintf(stderr, "\x1b[31m [!] \x1b[0minit requires an image path\n\n");
            return 1;
        }
        return stegolock_init(argv[2]);
    }
    else if (strcmp(command, "add") == 0) {
        if (argc != 4) {
            fprintf(stderr, "\x1b[31m [!] \x1b[0madd requires an image path and website\n\n");
            return 1;
        }
        return stegolock_add(argv[2], argv[3]);
    }
    else if (strcmp(command, "get") == 0) {
        if (argc != 4) {
            fprintf(stderr, "\x1b[31m [!] \x1b[0mget requires an image path and website\n\n");
            return 1;
        }
        return stegolock_get(argv[2], argv[3]);
    }
    else if (strcmp(command, "list") == 0) {
        if (argc != 3) {
            fprintf(stderr, "\x1b[31m [!] \x1b[0mlist requires an image path\n\n");
            return 1;
        }
        return stegolock_list(argv[2]);
    }
    else if (strcmp(command, "del") == 0) {
        if (argc != 4) {
            fprintf(stderr, "\x1b[31m [!] \x1b[0mdel requires an image path and website\n\n");
            return 1;
        }
        return stegolock_del(argv[2], argv[3]);
    }
    else if (strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        print_usage();
        return 0;
    }
    else {
        fprintf(stderr, "\x1b[31m [!] \x1b[0mUnknown command: %s\n", command);
        print_usage();
        return 1;
    }
}