#include "steganography.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BMP_HEADER_SIZE 54
#define BITS_PER_BYTE 8


typedef struct {
    uint16_t signature;
    uint32_t file_size;
    uint16_t reserved1;
    uint16_t reserved2;
    uint32_t pixel_offset;
} BMP_FILE_HEADER;



typedef struct {
    uint32_t header_size;
    int32_t width;
    int32_t height;
    uint16_t planes;
    uint16_t bits_per_pixel;
    uint32_t compression;
    uint32_t image_size;
    int32_t x_pixels_per_meter;
    int32_t y_pixels_per_meter;
    uint32_t colors_used;
    uint32_t colors_important;
} BMP_INFO_HEADER;



// Read BMP headers from file
static int read_bmp_headers(FILE *file, BMP_FILE_HEADER *fh, BMP_INFO_HEADER *ih) {
    if (fread(fh, sizeof(BMP_FILE_HEADER), 1, file) != 1) {
        return -1;
    }
    if (fread(ih, sizeof(BMP_INFO_HEADER), 1, file) != 1) {
        return -1;
    }
    return 0;
}



// Write BMP headers to file
static int write_bmp_headers(FILE *file, const BMP_FILE_HEADER *fh, const BMP_INFO_HEADER *ih) {
    if (fwrite(fh, sizeof(BMP_FILE_HEADER), 1, file) != 1) {
        return -1;
    }
    if (fwrite(ih, sizeof(BMP_INFO_HEADER), 1, file) != 1) {
        return -1;
    }
    return 0;
}



// Calculate bytes available
static size_t get_pixel_data_size(const BMP_INFO_HEADER *ih) {
    size_t width = (size_t)ih->width;
    size_t height = (size_t)ih->height;
    if (height < 0) height = -height;
    
    // 24-bit BMP: 3 bytes per pixel
    // 3 lsb bits per pixel
    size_t total_bytes = width * height * 3;
    return total_bytes / BITS_PER_BYTE;
}



int embed_data(const char *input_image_path, const char *output_image_path,
               const unsigned char *data, size_t data_len) {
    
    FILE *input_file = fopen(input_image_path, "rb");
    if (!input_file) {
        fprintf(stderr, "Error: Cannot open input image\n");
        return -1;
    }
    
    BMP_FILE_HEADER fh;
    BMP_INFO_HEADER ih;
    
    if (read_bmp_headers(input_file, &fh, &ih) != 0) {
        fprintf(stderr, "Error: Cannot read BMP headers\n");
        fclose(input_file);
        return -1;
    }
    
    if (fh.signature != 0x4D42) {  // BM
        fprintf(stderr, "Error: Not a valid BMP file\n");
        fclose(input_file);
        return -1;
    }
    
    if (ih.bits_per_pixel != 24) {
        fprintf(stderr, "Error: Only 24-bit BMP files are supported\n");
        fclose(input_file);
        return -1;
    }
    
    size_t max_size = get_pixel_data_size(&ih);
    if (data_len + sizeof(size_t) > max_size) {
        fprintf(stderr, "Error: Image too small for data\n");
        fclose(input_file);
        return -1;
    }
    
    // Read pixel data
    size_t pixel_data_size = fh.file_size - fh.pixel_offset;
    unsigned char *pixel_data = (unsigned char *)malloc(pixel_data_size);
    if (!pixel_data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(input_file);
        return -1;
    }
    
    if (fseek(input_file, fh.pixel_offset, SEEK_SET) != 0) {
        fprintf(stderr, "Error: Seek failed\n");
        free(pixel_data);
        fclose(input_file);
        return -1;
    }
    
    if (fread(pixel_data, pixel_data_size, 1, input_file) != 1) {
        fprintf(stderr, "Error: Cannot read pixel data\n");
        free(pixel_data);
        fclose(input_file);
        return -1;
    }
    
    fclose(input_file);
    
    // Prepare data to embed: size header + data
    unsigned char *embed_buffer = (unsigned char *)malloc(sizeof(size_t) + data_len);
    if (!embed_buffer) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(pixel_data);
        return -1;
    }
    
    memcpy(embed_buffer, &data_len, sizeof(size_t));
    memcpy(embed_buffer + sizeof(size_t), data, data_len);
    size_t total_embed_len = sizeof(size_t) + data_len;
    
    // Embed data into lsbs
    size_t bit_pos = 0;
    for (size_t i = 0; i < total_embed_len; i++) {
        for (int bit = 0; bit < BITS_PER_BYTE; bit++) {
            unsigned char bit_val = (embed_buffer[i] >> bit) & 1;
            size_t byte_idx = bit_pos / BITS_PER_BYTE;
            int bit_idx = bit_pos % BITS_PER_BYTE;
            
            // Clear lsb and set new bit
            pixel_data[byte_idx] = (pixel_data[byte_idx] & ~1) | bit_val;
            bit_pos++;
        }
    }
    
    // Write output file
    FILE *output_file = fopen(output_image_path, "wb");
    if (!output_file) {
        fprintf(stderr, "Error: Cannot create output file\n");
        free(pixel_data);
        free(embed_buffer);
        return -1;
    }
    
    if (write_bmp_headers(output_file, &fh, &ih) != 0) {
        fprintf(stderr, "Error: Cannot write BMP headers\n");
        fclose(output_file);
        free(pixel_data);
        free(embed_buffer);
        return -1;
    }
    
    if (fseek(output_file, fh.pixel_offset, SEEK_SET) != 0) {
        fprintf(stderr, "Error: Seek failed\n");
        fclose(output_file);
        free(pixel_data);
        free(embed_buffer);
        return -1;
    }
    
    if (fwrite(pixel_data, pixel_data_size, 1, output_file) != 1) {
        fprintf(stderr, "Error: Cannot write pixel data\n");
        fclose(output_file);
        free(pixel_data);
        free(embed_buffer);
        return -1;
    }
    
    fclose(output_file);
    free(pixel_data);
    free(embed_buffer);
    
    return 0;
}



unsigned char *extract_data(const char *image_path, size_t *data_len) {
    
    FILE *file = fopen(image_path, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open image file\n");
        return NULL;
    }
    
    BMP_FILE_HEADER fh;
    BMP_INFO_HEADER ih;
    
    if (read_bmp_headers(file, &fh, &ih) != 0) {
        fprintf(stderr, "Error: Cannot read BMP headers\n");
        fclose(file);
        return NULL;
    }
    
    if (fh.signature != 0x4D42) {
        fprintf(stderr, "Error: Not a valid BMP file\n");
        fclose(file);
        return NULL;
    }
    
    if (ih.bits_per_pixel != 24) {
        fprintf(stderr, "Error: Only 24-bit BMP files are supported\n");
        fclose(file);
        return NULL;
    }
    
    // Read pixel data
    size_t pixel_data_size = fh.file_size - fh.pixel_offset;
    unsigned char *pixel_data = (unsigned char *)malloc(pixel_data_size);
    if (!pixel_data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        return NULL;
    }
    
    if (fseek(file, fh.pixel_offset, SEEK_SET) != 0) {
        fprintf(stderr, "Error: Seek failed\n");
        free(pixel_data);
        fclose(file);
        return NULL;
    }
    
    if (fread(pixel_data, pixel_data_size, 1, file) != 1) {
        fprintf(stderr, "Error: Cannot read pixel data\n");
        free(pixel_data);
        fclose(file);
        return NULL;
    }
    
    fclose(file);
    
    // Extract length
    size_t length = 0;
    size_t bit_pos = 0;
    for (size_t i = 0; i < sizeof(size_t); i++) {
        for (int bit = 0; bit < BITS_PER_BYTE; bit++) {
            size_t byte_idx = bit_pos / BITS_PER_BYTE;
            int bit_idx = bit_pos % BITS_PER_BYTE;
            unsigned char bit_val = (pixel_data[byte_idx] >> 0) & 1;
            length |= ((size_t)bit_val << (i * BITS_PER_BYTE + bit));
            bit_pos++;
        }
    }
    
    if (length > pixel_data_size || length == 0) {
        fprintf(stderr, "Error: Invalid embedded data\n");
        free(pixel_data);
        return NULL;
    }
    
    // Extract data
    unsigned char *extracted = (unsigned char *)malloc(length);
    if (!extracted) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(pixel_data);
        return NULL;
    }
    
    for (size_t i = 0; i < length; i++) {
        for (int bit = 0; bit < BITS_PER_BYTE; bit++) {
            size_t byte_idx = bit_pos / BITS_PER_BYTE;
            unsigned char bit_val = (pixel_data[byte_idx] >> 0) & 1;
            extracted[i] |= (bit_val << bit);
            bit_pos++;
        }
    }
    
    *data_len = length;
    free(pixel_data);
    return extracted;
}



size_t get_max_size(const char *image_path) {
    
    FILE *file = fopen(image_path, "rb");
    if (!file) {
        return 0;
    }
    
    BMP_FILE_HEADER fh;
    BMP_INFO_HEADER ih;
    
    if (read_bmp_headers(file, &fh, &ih) != 0) {
        fclose(file);
        return 0;
    }
    
    fclose(file);
    
    if (fh.signature != 0x4D42 || ih.bits_per_pixel != 24) {
        return 0;
    }
    
    return get_pixel_data_size(&ih);
}
