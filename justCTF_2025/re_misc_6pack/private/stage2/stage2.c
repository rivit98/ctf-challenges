#include <stdio.h>
#include <windows.h>
#include <stdint.h>

#define FAIL(prefix_)       \
    do                      \
    {                       \
        exit(1);            \
    } while (0)


#define CHECKED_CALL(func)      \
    do                          \
    {                           \
        if((func) < 0)          \
            FAIL(#func);        \
    } while (0)

#define EI_NIDENT 16

#pragma pack(push, 1)
typedef struct {
  unsigned char e_ident[EI_NIDENT];
  unsigned short e_type;
  unsigned short e_machine;
  unsigned int e_version;
  unsigned long long e_entry;
  unsigned long long e_phoff;
  unsigned long long e_shoff;
  unsigned int e_flags;
  unsigned short e_ehsize;
  unsigned short e_phentsize;
  unsigned short e_phnum;
  unsigned short e_shentsize;
  unsigned short e_shnum;
  unsigned short e_shstrndx;
} Elf64_Ehdr;

typedef struct {
  unsigned int sh_name;
  unsigned int sh_type;
  unsigned long long sh_flags;
  unsigned long long sh_addr;
  unsigned long long sh_offset;
  unsigned long long sh_size;
  unsigned int sh_link;
  unsigned int sh_info;
  unsigned long long sh_addralign;
  unsigned long long sh_entsize;
} Elf64_Shdr;
#pragma pack(pop)

typedef struct {
  DWORD Length;
  DWORD MaximumLength;
  PVOID Buffer;
} buffer_t;

int read_section(buffer_t *ret) {
  FILE *fp = fopen("./6-pack", "rb");
  if (!fp) {
    return 1;
  }

  Elf64_Ehdr ehdr;
  CHECKED_CALL(fread(&ehdr, sizeof(ehdr), 1, fp));

  /* Read section header string table */
  Elf64_Shdr shstrtab;
  CHECKED_CALL(fseek(fp, ehdr.e_shoff + ehdr.e_shstrndx * ehdr.e_shentsize, SEEK_SET));
  CHECKED_CALL(fread(&shstrtab, sizeof(shstrtab), 1, fp));

  /* Load section names */
  char *shstrtab_data = malloc(shstrtab.sh_size);
  CHECKED_CALL(fseek(fp, shstrtab.sh_offset, SEEK_SET));
  CHECKED_CALL(fread(shstrtab_data, shstrtab.sh_size, 1, fp));

  for (int i = 0; i < ehdr.e_shnum; i++) {
    Elf64_Shdr shdr;
    CHECKED_CALL(fseek(fp, ehdr.e_shoff + i * ehdr.e_shentsize, SEEK_SET));
    CHECKED_CALL(fread(&shdr, sizeof(shdr), 1, fp));

    if (strcmp(shstrtab_data + shdr.sh_name, ".go.runtimeinfo") == 0) {
      ret->Buffer = malloc(shdr.sh_size);
      CHECKED_CALL(fseek(fp, shdr.sh_offset, SEEK_SET));
      CHECKED_CALL(fread(ret->Buffer, shdr.sh_size, 1, fp));
      ret->Length = shdr.sh_size;
      break;
    }
  }

  free(shstrtab_data);
  fclose(fp);

  return 0;
}

int rc4_decrypt(buffer_t *buffer, buffer_t *key) {
  HMODULE advapi32 = LoadLibraryA("advapi32.dll");
  if (!advapi32) {
    return 1;
  }

  NTSTATUS(WINAPI * SystemFunction033)(buffer_t *, buffer_t *) =
    GetProcAddress(advapi32, "SystemFunction033");

  if (!SystemFunction033) {
    return 1;
  }

  SystemFunction033(buffer, key);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    goto cleanup;
  }

  char *flag = argv[1];
  char *key_arg = argv[2];
  uint16_t k = atoi(key_arg);
  buffer_t sc = {0};
  LPVOID mem = NULL;
  int ret;

  ret = read_section(&sc);
  if (ret) {
    goto cleanup;
  }

  buffer_t key;
  key.Length = 2;
  key.Buffer = &k;

  if ((k >> 11) != 0xf || k & 0x1 == 0) {
    goto cleanup;
  }

  ret = rc4_decrypt(&sc, &key);
  if(ret) {
    goto cleanup;
  }

  mem = VirtualAlloc(NULL, sc.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!mem) {
    goto cleanup;
  }

  memcpy(mem, sc.Buffer, sc.Length);

  int (*func)(char *c) = (int (*)(char *c))mem;
  ret = func(flag);
  if (!ret) {
    puts("correct");
  } else {
    puts("nope");
  }

  cleanup:
  if(mem) VirtualFree(mem, 0, MEM_RELEASE);
  if(sc.Buffer) free(sc.Buffer);

  return ret;
}

