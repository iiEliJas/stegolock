#include "stegolock.h"
#include "stego/steganography.h"
#include "encr/encryption.h"
#include "encr/vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <conio.h>

static char *get_password(const char *prompt) {
    printf("%s", prompt);
    char *password = (char *)malloc(256);
    int i = 0;
    int ch;
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') {
            if (i > 0) i--;
        } else if (i < 255) {
            password[i++] = ch;
        }
    }
    password[i] = '\0';
    printf("\n");
    return password;
}



// Generate output filename from input
static char *generate_output_filename(const char *input_path) {
    char *output = (char *)malloc(512);
    if (!output) return NULL;
    
    strcpy(output, input_path);
    
    // Find extension
    char *dot = strrchr(output, '.');
    if (dot) {
        strcpy(dot, "_locked.bmp");
    } else {
        strcat(output, "_locked.bmp");
    }
    
    return output;
}



// Wrapper for embed_data 
int embed_data_stegolock(const char *input_image_path, const char *output_image_path,
                         const unsigned char *data, size_t data_len) {
    return embed_data(input_image_path, output_image_path, data, data_len);
}


//////////////////////////////////////////////////////////////////////////////////////////
///                     stegolock


int stegolock_init(const char *image_path) {
    printf("--- Stegolock Initialization ---\n\n");
    
    // Check image exists and capacity
    size_t max_size = get_max_size(image_path);
    if (max_size == 0) {
        fprintf(stderr, "Error: Cannot open image or invalid format\n");
        return -1;
    }
    
    // Get master password
    char *password1 = get_password("Enter master password: ");
    char *password2 = get_password("Confirm master password: ");
    
    if (strcmp(password1, password2) != 0) {
        fprintf(stderr, "Error: Passwords do not match\n");
        free(password1);
        free(password2);
        return -1;
    }
    
    // Create empty vault
    PasswordVault *vault = create_vault();
    if (!vault) {
        fprintf(stderr, "Error: Cannot create vault\n");
        free(password1);
        free(password2);
        return -1;
    }
    
    // Serialize vault
    size_t vault_size;
    unsigned char *vault_data = serialize_vault(vault, &vault_size);
    
    // Encrypt vault
    EncryptedData encrypted = encrypt_data(vault_data, vault_size, password1);
    
    if (!encrypted.ciphertext) {
        fprintf(stderr, "Error: Encryption failed\n");
        free(vault_data);
        free(password1);
        free(password2);
        free_vault(vault);
        return -1;
    }
    
    // Prepare data to embed (salt + iv + tag + ciphertext)
    size_t embed_size = SALT_SIZE + IV_SIZE + TAG_SIZE + encrypted.ciphertext_len;
    
    if (embed_size > max_size) {
        fprintf(stderr, "Error: Image too small for encrypted vault\n");
        free_encrypted_data(&encrypted);
        free(vault_data);
        free(password1);
        free(password2);
        free_vault(vault);
        return -1;
    }
    
    unsigned char *embed_data = (unsigned char *)malloc(embed_size);
    if (!embed_data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free_encrypted_data(&encrypted);
        free(vault_data);
        free(password1);
        free(password2);
        free_vault(vault);
        return -1;
    }
    
    size_t offset = 0;
    memcpy(embed_data + offset, encrypted.salt, SALT_SIZE);
    offset += SALT_SIZE;
    memcpy(embed_data + offset, encrypted.iv, IV_SIZE);
    offset += IV_SIZE;
    memcpy(embed_data + offset, encrypted.tag, TAG_SIZE);
    offset += TAG_SIZE;
    memcpy(embed_data + offset, encrypted.ciphertext, encrypted.ciphertext_len);
    
    // Embed into image
    char *output_path = generate_output_filename(image_path);
    
    if (embed_data_stegolock(image_path, output_path, embed_data, embed_size) != 0) {
        fprintf(stderr, "Error: Failed to embed data into image\n");
        free(embed_data);
        free(output_path);
        free_encrypted_data(&encrypted);
        free(vault_data);
        free(password1);
        free(password2);
        free_vault(vault);
        return -1;
    }
    
    printf("Vault initialized and embedded into %s\n", output_path);
    
    free(embed_data);
    free(output_path);
    free_encrypted_data(&encrypted);
    free(vault_data);
    free(password1);
    free(password2);
    free_vault(vault);
    
    return 0;
}

// Helper function to extract and decrypt vault
static PasswordVault *load_vault_from_image(const char *image_path, const char *password) {
    size_t embed_size;
    unsigned char *embed_data = extract_data(image_path, &embed_size);
    
    if (!embed_data) {
        fprintf(stderr, "Error: Cannot extract vault from image\n");
        return NULL;
    }
    
    if (embed_size < SALT_SIZE + IV_SIZE + TAG_SIZE) {
        fprintf(stderr, "Error: Invalid vault data\n");
        free(embed_data);
        return NULL;
    }
    
    // Parse embedded data
    EncryptedData encrypted;
    size_t offset = 0;
    
    memcpy(encrypted.salt, embed_data + offset, SALT_SIZE);
    offset += SALT_SIZE;
    memcpy(encrypted.iv, embed_data + offset, IV_SIZE);
    offset += IV_SIZE;
    memcpy(encrypted.tag, embed_data + offset, TAG_SIZE);
    offset += TAG_SIZE;
    
    encrypted.ciphertext_len = embed_size - offset;
    encrypted.ciphertext = embed_data + offset;
    
    // Decrypt vault
    size_t plaintext_len;
    unsigned char *plaintext = decrypt_data(&encrypted, password, &plaintext_len);
    
    if (!plaintext) {
        free(embed_data);
        return NULL;
    }
    
    // Deserialize vault
    PasswordVault *vault = deserialize_vault(plaintext, plaintext_len);
    
    free(plaintext);
    free(embed_data);
    
    return vault;
}

// Helper function to save vault back to image
static int save_vault_to_image(const char *image_path, PasswordVault *vault, const char *password) {
    // Serialize vault
    size_t vault_size;
    unsigned char *vault_data = serialize_vault(vault, &vault_size);
    
    // Encrypt vault
    EncryptedData encrypted = encrypt_data(vault_data, vault_size, password);
    
    if (!encrypted.ciphertext) {
        fprintf(stderr, "Error: Encryption failed\n");
        free(vault_data);
        return -1;
    }
    
    // Check image capacity
    size_t max_size = get_max_size(image_path);
    size_t embed_size = SALT_SIZE + IV_SIZE + TAG_SIZE + encrypted.ciphertext_len;
    
    if (embed_size > max_size) {
        fprintf(stderr, "Error: Image too small for updated vault\n");
        free_encrypted_data(&encrypted);
        free(vault_data);
        return -1;
    }
    
    // Prepare embedding data
    unsigned char *embed_data = (unsigned char *)malloc(embed_size);
    if (!embed_data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free_encrypted_data(&encrypted);
        free(vault_data);
        return -1;
    }
    
    size_t offset = 0;
    memcpy(embed_data + offset, encrypted.salt, SALT_SIZE);
    offset += SALT_SIZE;
    memcpy(embed_data + offset, encrypted.iv, IV_SIZE);
    offset += IV_SIZE;
    memcpy(embed_data + offset, encrypted.tag, TAG_SIZE);
    offset += TAG_SIZE;
    memcpy(embed_data + offset, encrypted.ciphertext, encrypted.ciphertext_len);
    
    // Embed into image
    char *output_path = generate_output_filename(image_path);
    
    if (embed_data_stegolock(image_path, output_path, embed_data, embed_size) != 0) {
        fprintf(stderr, "Error: Failed to save vault\n");
        free(embed_data);
        free(output_path);
        free_encrypted_data(&encrypted);
        free(vault_data);
        return -1;
    }
    
    printf("Vault updated and saved to %s\n", output_path);
    
    free(embed_data);
    free(output_path);
    free_encrypted_data(&encrypted);
    free(vault_data);
    
    return 0;
}

int stegolock_add(const char *image_path, const char *website) {
    char *password = get_password("Enter master password: ");
    
    PasswordVault *vault = load_vault_from_image(image_path, password);
    if (!vault) {
        free(password);
        return -1;
    }
    
    char username[MAX_USERNAME_LEN];
    char vault_password[MAX_PASSWORD_LEN];
    
    printf("Enter username for %s: ", website);
    fgets(username, MAX_USERNAME_LEN, stdin);
    username[strcspn(username, "\n")] = 0;
    
    char *pass = get_password("Enter password: ");
    strncpy(vault_password, pass, MAX_PASSWORD_LEN - 1);
    free(pass);
    
    if (vault_add_entry(vault, website, username, vault_password) != 0) {
        free_vault(vault);
        free(password);
        return -1;
    }
    
    if (save_vault_to_image(image_path, vault, password) != 0) {
        free_vault(vault);
        free(password);
        return -1;
    }
    
    printf("Entry for %s added\n", website);
    
    free_vault(vault);
    free(password);
    return 0;
}

int stegolock_get(const char *image_path, const char *website) {
    char *password = get_password("Enter master password: ");
    
    PasswordVault *vault = load_vault_from_image(image_path, password);
    if (!vault) {
        free(password);
        return -1;
    }
    
    VaultEntry *entry = vault_get_entry(vault, website);
    if (!entry) {
        fprintf(stderr, "Error: Entry for %s not found\n", website);
        free_vault(vault);
        free(password);
        return -1;
    }
    
    printf("Username for %s: %s\n", website, entry->username);
    printf("Password for %s: %s\n", website, entry->password);
    
    free_vault(vault);
    free(password);
    return 0;
}

int stegolock_list(const char *image_path) {
    char *password = get_password("Enter master password: ");
    
    PasswordVault *vault = load_vault_from_image(image_path, password);
    if (!vault) {
        free(password);
        return -1;
    }
    
    vault_list_entries(vault);
    
    free_vault(vault);
    free(password);
    return 0;
}

int stegolock_del(const char *image_path, const char *website) {
    char *password = get_password("Enter master password: ");
    
    PasswordVault *vault = load_vault_from_image(image_path, password);
    if (!vault) {
        free(password);
        return -1;
    }
    
    if (vault_delete_entry(vault, website) != 0) {
        free_vault(vault);
        free(password);
        return -1;
    }
    
    if (save_vault_to_image(image_path, vault, password) != 0) {
        free_vault(vault);
        free(password);
        return -1;
    }
    
    printf("Entry for %s deleted\n", website);
    
    free_vault(vault);
    free(password);
    return 0;
}

