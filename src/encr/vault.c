#include "vault.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>



PasswordVault *create_vault(void) {
    PasswordVault *vault = (PasswordVault *)malloc(sizeof(PasswordVault));
    if (!vault) {
        return NULL;
    }
    memset(vault, 0, sizeof(PasswordVault));
    vault->entry_count = 0;
    return vault;
}



void free_vault(PasswordVault *vault) {
    if (vault) {
        free(vault);
    }
}



unsigned char *serialize_vault(const PasswordVault *vault, size_t *serialized_len) {
    if (!vault || !serialized_len) {
        return NULL;
    }
    
    // entry_count + entries
    size_t size = sizeof(uint32_t) + (vault->entry_count * 
                  (MAX_WEBSITE_LEN + MAX_USERNAME_LEN + MAX_PASSWORD_LEN));
    
    unsigned char *buffer = (unsigned char *)malloc(size);
    if (!buffer) {
        return NULL;
    }
    
    // Write entry count
    uint32_t count = vault->entry_count;
    memcpy(buffer, &count, sizeof(uint32_t));
    
    // Write entries
    size_t offset = sizeof(uint32_t);
    for (uint32_t i = 0; i < vault->entry_count; i++) {
        memcpy(buffer + offset, vault->entries[i].website, MAX_WEBSITE_LEN);
        offset += MAX_WEBSITE_LEN;
        
        memcpy(buffer + offset, vault->entries[i].username, MAX_USERNAME_LEN);
        offset += MAX_USERNAME_LEN;
        
        memcpy(buffer + offset, vault->entries[i].password, MAX_PASSWORD_LEN);
        offset += MAX_PASSWORD_LEN;
    }
    
    *serialized_len = size;
    return buffer;
}



PasswordVault *deserialize_vault(const unsigned char *data, size_t data_len) {
    if (!data || data_len < sizeof(uint32_t)) {
        return NULL;
    }
    
    PasswordVault *vault = create_vault();
    if (!vault) {
        return NULL;
    }
    
    // Read entry count
    uint32_t count;
    memcpy(&count, data, sizeof(uint32_t));
    
    if (count > MAX_ENTRIES) {
        free_vault(vault);
        return NULL;
    }
    
    vault->entry_count = count;
    
    // Read entries
    size_t offset = sizeof(uint32_t);
    for (uint32_t i = 0; i < count; i++) {
        if (offset + MAX_WEBSITE_LEN + MAX_USERNAME_LEN + MAX_PASSWORD_LEN > data_len) {
            free_vault(vault);
            return NULL;
        }
        
        memcpy(vault->entries[i].website, data + offset, MAX_WEBSITE_LEN);
        offset += MAX_WEBSITE_LEN;
        
        memcpy(vault->entries[i].username, data + offset, MAX_USERNAME_LEN);
        offset += MAX_USERNAME_LEN;
        
        memcpy(vault->entries[i].password, data + offset, MAX_PASSWORD_LEN);
        offset += MAX_PASSWORD_LEN;
    }
    
    return vault;
}



int vault_add_entry(PasswordVault *vault, const char *website,
                    const char *username, const char *password) {
    
    if (!vault || !website || !username || !password) {
        return -1;
    }
    
    if (vault->entry_count >= MAX_ENTRIES) {
        fprintf(stderr, "Error: Vault is full\n");
        return -1;
    }
    
    // Check if entry already exists
    for (uint32_t i = 0; i < vault->entry_count; i++) {
        if (strcmp(vault->entries[i].website, website) == 0) {
            fprintf(stderr, "Error: Entry for %s already exists\n", website);
            return -1;
        }
    }
    
    // Add new entry
    strncpy(vault->entries[vault->entry_count].website, website, MAX_WEBSITE_LEN - 1);
    vault->entries[vault->entry_count].website[MAX_WEBSITE_LEN - 1] = '\0';
    strncpy(vault->entries[vault->entry_count].username, username, MAX_USERNAME_LEN - 1);
    vault->entries[vault->entry_count].username[MAX_USERNAME_LEN - 1] = '\0';
    strncpy(vault->entries[vault->entry_count].password, password, MAX_PASSWORD_LEN - 1);
    vault->entries[vault->entry_count].password[MAX_PASSWORD_LEN - 1] = '\0';
    
    vault->entry_count++;
    return 0;
}



VaultEntry *vault_get_entry(PasswordVault *vault, const char *website) {
    if (!vault || !website) {
        return NULL;
    }
    
    for (uint32_t i = 0; i < vault->entry_count; i++) {
        if (strcmp(vault->entries[i].website, website) == 0) {
            return &vault->entries[i];
        }
    }
    
    return NULL;
}



int vault_delete_entry(PasswordVault *vault, const char *website) {
    if (!vault || !website) {
        return -1;
    }
    
    for (uint32_t i = 0; i < vault->entry_count; i++) {
        if (strcmp(vault->entries[i].website, website) == 0) {
            // Move last entry to this position
            if (i < vault->entry_count - 1) {
                memcpy(&vault->entries[i], &vault->entries[vault->entry_count - 1],
                       sizeof(VaultEntry));
            }
            vault->entry_count--;
            return 0;
        }
    }
    
    fprintf(stderr, "Error: Entry for %s not found\n", website);
    return -1;
}



void vault_list_entries(const PasswordVault *vault) {
    if (!vault) {
        return;
    }
    
    if (vault->entry_count == 0) {
        printf("Vault is empty\n");
        return;
    }
    
    printf("\n        Stored websites:\n");
    for (uint32_t i = 0; i < vault->entry_count; i++) {
        printf("            %u. %s\n", i + 1, vault->entries[i].website);
    }
    printf("\n");
}
