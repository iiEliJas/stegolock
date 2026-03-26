#ifndef STEGOLOCK_H
#define STEGOLOCK_H

// Initialize a new image vault
int stegolock_init(const char *image_path);

// Add entry to the image
int stegolock_add(const char *image_path, const char *website);

// Get entry from the image
int stegolock_get(const char *image_path, const char *website);

// List entries in the image
int stegolock_list(const char *image_path);

// Delete entry from the image
int stegolock_del(const char *image_path, const char *website);

#endif // STEGOLOCK_H
