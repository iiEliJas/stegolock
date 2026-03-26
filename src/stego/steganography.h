#ifndef STEGANOGRAPHY_H
#define STEGANOGRAPHY_H

#include <stdint.h>
#include <stddef.h>

// Embeds data into a 24-bit BMP image using lsb steganography
// Returns 0 on success and -1 on failure
int embed_data(const char *input_image_path, const char *output_image_path,
               const unsigned char *data, size_t data_len);

// Extracts embedded data from a 24-bit BMP image
// Returns pointer to extracted data on success, NULL on failure
// Sets data_len to the extracted data size
unsigned char *extract_data(const char *image_path, size_t *data_len);

// Calculates maximum bytes that can be embedded in a BMP image
// Returns 0 on failure
size_t get_max_size(const char *image_path);

#endif // STEGANOGRAPHY_H
