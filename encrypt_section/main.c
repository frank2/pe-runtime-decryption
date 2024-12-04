#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <windows.h>

#pragma comment(lib, "rpcrt4.lib")

char *keygen(void) {
   UUID uuid_gen;
   UuidCreate(&uuid_gen);

   RPC_CSTR uuid_rpc;
   UuidToStringA(&uuid_gen, &uuid_rpc);

   return (char *)uuid_rpc;
}

void print_help(void) {
   puts("[encrypt_section]\n\n"
        "-h               this help message\n"
        "-b <binary>      the binary to encrypt\n"
        "-x <section>     the executable section to encrypt\n"
        "-d <section>     the data section to encrypt\n"
        "-H <filename>    the header file to dump the key into\n"
        "-k <filename>    the text file to dump the key into\n"
        "-s <section>     the section in the binary to insert the key into\n");
}

int parse_argv(int argc, char *argv[], char **binary, char **exec_section, char **data_section, char **header_file, char **flat_file, char **key_section) {
   for (size_t i=1; i<argc; ++i) {
      if (strncmp(argv[i], "-h", 2) == 0) {
         print_help();
         return 0;
      }
      else if (strncmp(argv[i], "-b", 2) == 0)
         *binary = argv[++i];
      else if (strncmp(argv[i], "-x", 2) == 0)
         *exec_section = argv[++i];
      else if (strncmp(argv[i], "-d", 2) == 0)
         *data_section = argv[++i];
      else if (strncmp(argv[i], "-H", 2) == 0)
         *header_file = argv[++i];
      else if (strncmp(argv[i], "-k", 2) == 0)
         *flat_file = argv[++i];
      else if (strncmp(argv[i], "-s", 2) == 0)
         *key_section = argv[++i];
      else {
         printf("unknown switch: %s\n", argv[i]);
         print_help();
         return -1;
      }
   }

   return 1;
}

void rc4(uint8_t *ciphertext, size_t ciphertext_size, const uint8_t *key, size_t key_size) {
   uint8_t sbox[256];

   for (size_t i=0; i<256; ++i)
      sbox[i] = i;

   size_t j = 0;
   
   for (size_t i=0; i<256; ++i) {
      j = (j + sbox[i] + key[i % key_size]) % 256;
      uint8_t tmp = sbox[i];
      sbox[i] = sbox[j];
      sbox[j] = tmp;
   }

   j = 0;
   
   for (size_t i=0; i<ciphertext_size; ++i) {
      size_t k = (i + 1) % 256;
      j = (j + sbox[k]) % 256;
      uint8_t tmp = sbox[k];
      sbox[k] = sbox[j];
      sbox[j] = tmp;
      ciphertext[i] ^= sbox[(sbox[j] + sbox[k]) % 256];
   }
}

uint8_t *load_binary(const char *filename, size_t *size_ptr) {
   HANDLE bin_handle = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

   if (bin_handle == INVALID_HANDLE_VALUE)
      return NULL;

   *size_ptr = GetFileSize(bin_handle, NULL);
   uint8_t *buffer = (uint8_t *)malloc(*size_ptr);
   DWORD bytes_read;

   if (!ReadFile(bin_handle, buffer, (DWORD)*size_ptr, &bytes_read, NULL)) {
      free(buffer);
      CloseHandle(bin_handle);
      *size_ptr = 0;
      return NULL;
   }

   CloseHandle(bin_handle);

   return buffer;
}

bool encrypt_section(uint8_t *bin_data, size_t bin_size, const char *section, const char *key) {
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)bin_data;
   PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER)&bin_data[dos_header->e_lfanew+sizeof(DWORD)];
   PIMAGE_SECTION_HEADER section_table = (PIMAGE_SECTION_HEADER)&bin_data[dos_header->e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+file_header->SizeOfOptionalHeader];

   for (size_t i=0; i<file_header->NumberOfSections; ++i) {
      if (memcmp(&section_table[i].Name[0], &section[0], strlen(section)) != 0)
         continue;

      rc4(&bin_data[section_table[i].PointerToRawData], section_table[i].SizeOfRawData, (const uint8_t *)key, strlen(key));

      return true;
   }

   return false;
}

bool encrypt_binary(uint8_t *bin_data, size_t bin_size, const char *text_section, const char *data_section, const char *key) {
   if (!encrypt_section(bin_data, bin_size, text_section, key))
      return false;
   
   if (!encrypt_section(bin_data, bin_size, data_section, key))
      return false;

   return true;
}

void dump_header_file(const char *header_file, const char *key) {
   char header_buff[8192];

   memset(&header_buff[0], 0, 8192);
   snprintf(header_buff, 8192, "#pragma once\n\n#define RC4_KEY \"%s\"\n", key);

   HANDLE header_handle = CreateFileA(header_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

   if (header_handle == INVALID_HANDLE_VALUE) {
      puts("error: couldn't open header file for writing");
      ExitProcess(1);
   }

   DWORD bytes_written;

   if (!WriteFile(header_handle, header_buff, strlen(header_buff), &bytes_written, NULL)) {
      puts("error: couldn't write to header file");
      ExitProcess(1);
   }
}

void dump_flat_file(const char *filename, const char *key) {
   HANDLE file_handle = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

   if (file_handle == INVALID_HANDLE_VALUE) {
      puts("error: couldn't open flat file for writing");
      ExitProcess(1);
   }

   char file_buff[512];
   snprintf(file_buff, 512, "%s\n", key);

   DWORD bytes_written;

   if (!WriteFile(file_handle, file_buff, strlen(file_buff), &bytes_written, NULL)) {
      puts("error: failed to write flat file");
      ExitProcess(1);
   }
}

void insert_key_section(uint8_t *bin_data, size_t bin_size, const char *key_section, const char *key) {
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)bin_data;
   PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER)&bin_data[dos_header->e_lfanew+sizeof(DWORD)];
   PIMAGE_SECTION_HEADER section_table = (PIMAGE_SECTION_HEADER)&bin_data[dos_header->e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+file_header->SizeOfOptionalHeader];

   for (size_t i=0; i<file_header->NumberOfSections; ++i) {
      if (memcmp(&section_table[i].Name[0], key_section, strlen(key_section)) != 0)
         continue;

      memcpy(&bin_data[section_table[i].PointerToRawData], key, strlen(key));
      return;
   }

   printf("error: key section not found: %s\n", key_section);
}

int main(int argc, char *argv[]) {
   if (argc <= 1) {
      print_help();
      return 0;
   }

   char *binary = NULL;
   char *exec_section = NULL;
   char *data_section = NULL;
   char *header_file = NULL;
   char *flat_file = NULL;
   char *key_section = NULL;
   int result = parse_argv(argc, argv, &binary, &exec_section, &data_section, &header_file, &flat_file, &key_section);

   if (result != 1)
      return 1;
   
   if (binary == NULL) {
      puts("error: no binary provided");
      print_help();
      return 1;
   }
   if (exec_section == NULL) {
      puts("error: no executable section to encrypt");
      print_help();
      return 1;
   }
   if (data_section == NULL) {
      puts("error: no data section to encrypt");
      print_help();
      return 1;
   }
   if (header_file == NULL && flat_file == NULL && key_section == NULL) {
      puts("error: nowhere to place the encryption key");
      print_help();
      return 1;
   }

   char *key = keygen();
   printf("[+] keygen: %s\n", key);
   
   size_t bin_size = 0;
   uint8_t *bin_data = load_binary(binary, &bin_size);

   if (bin_data == NULL) {
      puts("error: binary load with read privileges failed");
      return 1;
   }

   printf("[+] encrypting binary...");
   
   if (!encrypt_binary(bin_data, bin_size, exec_section, data_section, key)) {
      puts("error: exec or data section failed to encrypt");
      return 1;
   }

   puts("done.");

   if (header_file != NULL) {
      printf("[+] dumping header %s...", header_file);
      dump_header_file(header_file, key);
      puts("done.");
   }

   if (flat_file != NULL) {
      printf("[+] dumping flat file %s...", flat_file);
      dump_flat_file(flat_file, key);
      puts("done.");
   }

   if (key_section != NULL) {
      printf("[+] inserting key into section %s...", key_section);
      insert_key_section(bin_data, bin_size, key_section, key);
      puts("done.");
   }

   printf("[+] rewriting %s...", binary);

   HANDLE binary_handle = CreateFileA(binary, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

   if (binary_handle == INVALID_HANDLE_VALUE) {
      puts("error: couldn't open file for writing");
      return 1;
   }

   DWORD bytes_written;

   if (!WriteFile(binary_handle, bin_data, bin_size, &bytes_written, NULL)) {
      puts("error: couldn't write binary file");
      return 1;
   }

   puts("done.");
   CloseHandle(binary_handle);

   printf("[+] %s encrypted\n", binary);
   return 0;
}
