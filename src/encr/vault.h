#ifndef VAULT_H
#define VAULT_H

#include <stdint.h>
#include <stddef.h>

#define MAX_ENTRIES 256
#define MAX_WEBSITE_LEN 256
#define MAX_USERNAME_LEN 256
#define MAX_PASSWORD_LEN 256


typedef struct {
    char website[MAX_WEBSITE_LEN];
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
} VaultEntry;


typedef struct {
    VaultEntry entries[MAX_ENTRIES];
    uint32_t entry_count;
} PasswordVault;


PasswordVault *create_vault(void);


void free_vault(PasswordVault *vault);


unsigned char *serialize_vault(const PasswordVault *vault, size_t *serialized_len);


PasswordVault *deserialize_vault(const unsigned char *data, size_t data_len);


int vault_add_entry(PasswordVault *vault, const char *website, const char *username, const char *password);


VaultEntry *vault_get_entry(PasswordVault *vault, const char *website);


int vault_delete_entry(PasswordVault *vault, const char *website);


void vault_list_entries(const PasswordVault *vault);

#endif // VAULT_H
