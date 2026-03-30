#include "stegolock.h"
#include "stego/steganography.h"
#include "encr/encryption.h"
#include "encr/aes256gcm.h"
#include "encr/vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>

// ---------------------------------------------------------------------------
//  ANSI color codes
// ---------------------------------------------------------------------------

#define CLR_RESET  "\x1b[0m"
#define CLR_BOLD   "\x1b[1m"
#define CLR_DIM    "\x1b[2m"
#define CLR_GREEN  "\x1b[32m"
#define CLR_RED    "\x1b[31m"
#define CLR_YELLOW "\x1b[33m"
#define CLR_CYAN   "\x1b[36m"
#define CLR_WHITE  "\x1b[97m"

#define MSG_OK   CLR_GREEN  " [+] " CLR_RESET
#define MSG_ERR  CLR_RED    " [!] " CLR_RESET
#define MSG_INFO CLR_CYAN   " [*] " CLR_RESET
#define MSG_WARN CLR_YELLOW " [~] " CLR_RESET

//////////////////////////////////////////////////////////////////////////////
//  Password prompt with masked input
//
static char* get_password(const char* prompt) {
    printf("       " CLR_CYAN "%s" CLR_RESET, prompt);
    fflush(stdout);

    char* password = (char*)malloc(256);
    if (!password) return NULL;

    int i = 0;
    int ch;
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') {
            if (i > 0) {
                i--;
                printf("\b \b");
                fflush(stdout);
            }
        }
        else if (i < 255) {
            password[i++] = ch;
            printf("*");
            fflush(stdout);
        }
    }
    password[i] = '\0';
    printf("\n");
    return password;
}

//////////////////////////////////////////////////////////////////////////////
//  Filename helpers
//

static char* generate_backup_filename(const char* input_path) {
    char* output = (char*)malloc(512);
    if (!output) return NULL;

    strcpy(output, input_path);

    char* dot = strrchr(output, '.');
    if (dot)
        strcpy(dot, "_old.bmp");
    else
        strcat(output, "_old.bmp");

    return output;
}

//////////////////////////////////////////////////////////////////////////////
//  embed_data wrapper
//

int embed_data_stegolock(const char* input_image_path, const char* output_image_path,
    const unsigned char* data, size_t data_len) {
    return embed_data(input_image_path, output_image_path, data, data_len);
}

// //////////////////////////////////////////////////////////////////////////////
//  stegolock
//

int stegolock_init(const char* image_path) {
    printf("\n" MSG_INFO CLR_BOLD "Initializing vault" CLR_RESET " in %s\n\n", image_path);

    size_t max_size = get_max_size(image_path);
    if (max_size == 0) {
        fprintf(stderr, MSG_ERR "Cannot open image or invalid format\n\n");
        return -1;
    }

    char* password1 = get_password("Master password  : ");
    char* password2 = get_password("Confirm password : ");
    printf("\n");

    if (strcmp(password1, password2) != 0) {
        fprintf(stderr, MSG_ERR "Passwords do not match\n\n");
        free(password1);
        free(password2);
        return -1;
    }

    PasswordVault* vault = create_vault();
    if (!vault) {
        fprintf(stderr, MSG_ERR "Failed to create vault\n\n");
        free(password1);
        free(password2);
        return -1;
    }

    size_t vault_size;
    unsigned char* vault_data = serialize_vault(vault, &vault_size);

    EncryptedData encrypted = encrypt_data(vault_data, vault_size, password1);
    if (!encrypted.ciphertext) {
        fprintf(stderr, MSG_ERR "Encryption failed\n\n");
        secure_zero(vault_data, vault_size);
        free(vault_data);
        free(password1);
        free(password2);
        free_vault(vault);
        return -1;
    }

    size_t embed_size = SALT_SIZE + IV_SIZE + TAG_SIZE + encrypted.ciphertext_len;
    if (embed_size > max_size) {
        fprintf(stderr, MSG_ERR "Image too small to hold the encrypted vault\n\n");
        free_encrypted_data(&encrypted);
        secure_zero(&encrypted, sizeof(encrypted));
        secure_zero(vault_data, vault_size);
        free(vault_data);
        free(password1);
        free(password2);
        free_vault(vault);
        return -1;
    }

    unsigned char* embed_data = (unsigned char*)malloc(embed_size);
    if (!embed_data) {
        fprintf(stderr, MSG_ERR "Memory allocation failed\n\n");
        free_encrypted_data(&encrypted);
        secure_zero(&encrypted, sizeof(encrypted));
        secure_zero(vault_data, vault_size);
        free(vault_data);
        free(password1);
        free(password2);
        free_vault(vault);
        return -1;
    }

    size_t offset = 0;
    memcpy(embed_data + offset, encrypted.salt, SALT_SIZE);              offset += SALT_SIZE;
    memcpy(embed_data + offset, encrypted.iv, IV_SIZE);                offset += IV_SIZE;
    memcpy(embed_data + offset, encrypted.tag, TAG_SIZE);               offset += TAG_SIZE;
    memcpy(embed_data + offset, encrypted.ciphertext, encrypted.ciphertext_len);

    char* backup_path = generate_backup_filename(image_path);
    remove(backup_path);

    if (rename(image_path, backup_path) != 0) {
        fprintf(stderr, MSG_ERR "Failed to back up original image\n\n");
        secure_zero(embed_data, embed_size);
        secure_zero(vault_data, vault_size);
        free(embed_data);
        free(backup_path);
        free_encrypted_data(&encrypted);
        secure_zero(&encrypted, sizeof(encrypted));
        free(vault_data);
        free(password1);
        free(password2);
        free_vault(vault);
        return -1;
    }

    if (embed_data_stegolock(backup_path, image_path, embed_data, embed_size) != 0) {
        fprintf(stderr, MSG_ERR "Failed to embed vault into image\n\n");
        rename(backup_path, image_path);
        secure_zero(embed_data, embed_size);
        secure_zero(vault_data, vault_size);
        free(embed_data);
        free(backup_path);
        free_encrypted_data(&encrypted);
        secure_zero(&encrypted, sizeof(encrypted));
        free(vault_data);
        free(password1);
        free(password2);
        free_vault(vault);
        return -1;
    }

    printf(MSG_OK CLR_BOLD "Vault created" CLR_RESET "  ->  " CLR_WHITE "%s" CLR_RESET "\n", image_path);
    printf(MSG_WARN        "Backup saved   ->  " CLR_DIM "%s" CLR_RESET "\n\n", backup_path);

    secure_zero(embed_data, embed_size);
    secure_zero(vault_data, vault_size);
    free(embed_data);
    free(backup_path);
    free_encrypted_data(&encrypted);
    secure_zero(&encrypted, sizeof(encrypted));
    free(vault_data);
    free(password1);
    free(password2);
    free_vault(vault);

    return 0;
}

// ---------------------------------------------------------------------------

static PasswordVault* load_vault_from_image(const char* image_path, const char* password) {
    size_t embed_size;
    unsigned char* embed_data = extract_data(image_path, &embed_size);

    if (!embed_data) {
        fprintf(stderr, MSG_ERR "Cannot read vault from %s\n\n", image_path);
        return NULL;
    }

    if (embed_size < SALT_SIZE + IV_SIZE + TAG_SIZE) {
        fprintf(stderr, MSG_ERR "No valid vault found in image\n\n");
        free(embed_data);
        return NULL;
    }

    EncryptedData encrypted;
    size_t offset = 0;

    memcpy(encrypted.salt, embed_data + offset, SALT_SIZE); offset += SALT_SIZE;
    memcpy(encrypted.iv, embed_data + offset, IV_SIZE);   offset += IV_SIZE;
    memcpy(encrypted.tag, embed_data + offset, TAG_SIZE);  offset += TAG_SIZE;

    encrypted.ciphertext_len = embed_size - offset;
    encrypted.ciphertext = embed_data + offset;

    size_t plaintext_len;
    unsigned char* plaintext = decrypt_data(&encrypted, password, &plaintext_len);

    if (!plaintext) {
        fprintf(stderr, MSG_ERR "Decryption failed -- wrong master password?\n\n");
        free(embed_data);
        return NULL;
    }

    PasswordVault* vault = deserialize_vault(plaintext, plaintext_len);

    secure_zero(plaintext, plaintext_len);
    free(plaintext);
    free(embed_data);

    return vault;
}

static int save_vault_to_image(const char* image_path, PasswordVault* vault, const char* password) {
    size_t vault_size;
    unsigned char* vault_data = serialize_vault(vault, &vault_size);

    EncryptedData encrypted = encrypt_data(vault_data, vault_size, password);
    if (!encrypted.ciphertext) {
        fprintf(stderr, MSG_ERR "Encryption failed\n\n");
        secure_zero(vault_data, vault_size);
        free(vault_data);
        return -1;
    }

    size_t max_size = get_max_size(image_path);
    size_t embed_size = SALT_SIZE + IV_SIZE + TAG_SIZE + encrypted.ciphertext_len;

    if (embed_size > max_size) {
        fprintf(stderr, MSG_ERR "Image too small for the updated vault\n\n");
        free_encrypted_data(&encrypted);
        secure_zero(&encrypted, sizeof(encrypted));
        secure_zero(vault_data, vault_size);
        free(vault_data);
        return -1;
    }

    unsigned char* embed_data = (unsigned char*)malloc(embed_size);
    if (!embed_data) {
        fprintf(stderr, MSG_ERR "Memory allocation failed\n\n");
        free_encrypted_data(&encrypted);
        secure_zero(&encrypted, sizeof(encrypted));
        secure_zero(vault_data, vault_size);
        free(vault_data);
        return -1;
    }

    size_t offset = 0;
    memcpy(embed_data + offset, encrypted.salt, SALT_SIZE);              offset += SALT_SIZE;
    memcpy(embed_data + offset, encrypted.iv, IV_SIZE);                offset += IV_SIZE;
    memcpy(embed_data + offset, encrypted.tag, TAG_SIZE);               offset += TAG_SIZE;
    memcpy(embed_data + offset, encrypted.ciphertext, encrypted.ciphertext_len);

    char* backup_path = generate_backup_filename(image_path);
    remove(backup_path);

    if (rename(image_path, backup_path) != 0) {
        fprintf(stderr, MSG_ERR "Failed to back up image\n\n");
        secure_zero(embed_data, embed_size);
        secure_zero(vault_data, vault_size);
        free(embed_data);
        free(backup_path);
        free_encrypted_data(&encrypted);
        secure_zero(&encrypted, sizeof(encrypted));
        free(vault_data);
        return -1;
    }

    if (embed_data_stegolock(backup_path, image_path, embed_data, embed_size) != 0) {
        fprintf(stderr, MSG_ERR "Failed to save vault\n\n");
        rename(backup_path, image_path);
        secure_zero(embed_data, embed_size);
        secure_zero(vault_data, vault_size);
        free(embed_data);
        free(backup_path);
        free_encrypted_data(&encrypted);
        secure_zero(&encrypted, sizeof(encrypted));
        free(vault_data);
        return -1;
    }

    secure_zero(embed_data, embed_size);
    secure_zero(vault_data, vault_size);
    free(embed_data);
    free(backup_path);
    free_encrypted_data(&encrypted);
    secure_zero(&encrypted, sizeof(encrypted));
    free(vault_data);

    return 0;
}

// ---------------------------------------------------------------------------

int stegolock_add(const char* image_path, const char* website) {
    printf("\n" MSG_INFO CLR_BOLD "Adding entry" CLR_RESET " for %s\n\n", website);

    char* password = get_password("Master password  : ");
    printf("\n");

    PasswordVault* vault = load_vault_from_image(image_path, password);
    if (!vault) {
        secure_zero(password, strlen(password)+1);
        free(password);
        return -1;
    }

    char username[MAX_USERNAME_LEN];
    char vault_password[MAX_PASSWORD_LEN];

    printf("       " CLR_CYAN "Username         : " CLR_RESET);
    fflush(stdout);
    fgets(username, MAX_USERNAME_LEN, stdin);
    username[strcspn(username, "\n")] = 0;

    char* pass = get_password("Site password    : ");
    printf("\n");
    strncpy(vault_password, pass, MAX_PASSWORD_LEN - 1);
    vault_password[MAX_PASSWORD_LEN - 1] = '\0';
    free(pass);

    if (vault_add_entry(vault, website, username, vault_password) != 0) {
        fprintf(stderr, MSG_ERR "Failed to add entry\n\n");
        free_vault(vault);
        secure_zero(password, strlen(password)+1);
        free(password);
        return -1;
    }

    if (save_vault_to_image(image_path, vault, password) != 0) {
        free_vault(vault);
        secure_zero(password, strlen(password)+1);
        free(password);
        return -1;
    }

    printf(MSG_OK CLR_BOLD "Entry saved" CLR_RESET "  ->  " CLR_WHITE "%s" CLR_RESET "\n\n", website);

    free_vault(vault);
    secure_zero(password, strlen(password)+1);
    free(password);
    return 0;
}

// ---------------------------------------------------------------------------

int stegolock_get(const char* image_path, const char* website) {
    printf("\n" MSG_INFO CLR_BOLD "Retrieving entry" CLR_RESET " for %s\n\n", website);

    char* password = get_password("Master password  : ");
    printf("\n");

    PasswordVault* vault = load_vault_from_image(image_path, password);
    if (!vault) {
        secure_zero(password, strlen(password)+1);
        free(password);
        return -1;
    }

    VaultEntry* entry = vault_get_entry(vault, website);
    if (!entry) {
        fprintf(stderr, MSG_ERR "No entry found for %s\n\n", website);
        free_vault(vault);
        secure_zero(password, strlen(password)+1);
        free(password);
        return -1;
    }

    printf("       %-16s " CLR_DIM "|" CLR_RESET "  %s\n",
        "Website", entry->website);
    printf("       %-16s " CLR_DIM "|" CLR_RESET "  %s\n",
        "Username", entry->username);
    printf("       %-16s " CLR_DIM "|" CLR_RESET "  " CLR_GREEN "%s" CLR_RESET "\n\n",
        "Password", entry->password);

    free_vault(vault);
    secure_zero(password, strlen(password)+1);
    free(password);
    return 0;
}



int stegolock_list(const char* image_path) {
    printf("\n" MSG_INFO CLR_BOLD "Vault contents" CLR_RESET " of %s\n\n", image_path);

    char* password = get_password("Master password  : ");
    printf("\n");

    PasswordVault* vault = load_vault_from_image(image_path, password);
    if (!vault) {
        secure_zero(password, strlen(password)+1);
        free(password);
        return -1;
    }

    printf("       " CLR_DIM "----------------------------------------" CLR_RESET "\n");
    vault_list_entries(vault);
    printf("       " CLR_DIM "----------------------------------------" CLR_RESET "\n\n");

    free_vault(vault);
    secure_zero(password, strlen(password)+1);
    free(password);
    return 0;
}

// ---------------------------------------------------------------------------

int stegolock_del(const char* image_path, const char* website) {
    printf("\n" MSG_INFO CLR_BOLD "Deleting entry" CLR_RESET " for %s\n\n", website);

    char* password = get_password("Master password  : ");
    printf("\n");

    PasswordVault* vault = load_vault_from_image(image_path, password);
    if (!vault) {
        secure_zero(password, strlen(password)+1);
        free(password);
        return -1;
    }

    if (vault_delete_entry(vault, website) != 0) {
        fprintf(stderr, MSG_ERR "No entry found for %s\n\n", website);
        free_vault(vault);
        secure_zero(password, strlen(password)+1);
        free(password);
        return -1;
    }

    if (save_vault_to_image(image_path, vault, password) != 0) {
        free_vault(vault);
        secure_zero(password, strlen(password)+1);
        free(password);
        return -1;
    }

    printf(MSG_OK CLR_BOLD "Entry deleted" CLR_RESET "  ->  " CLR_WHITE "%s" CLR_RESET "\n\n", website);

    free_vault(vault);
    secure_zero(password, strlen(password)+1);
    free(password);
    return 0;
}
