#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>

#define MAX_ELF_FILES 2

/* Global state */
int debug_mode = 0;
int current_fd[MAX_ELF_FILES] = {-1, -1};
void *map_start[MAX_ELF_FILES] = {NULL, NULL};
size_t file_size[MAX_ELF_FILES] = {0, 0};
char *file_name[MAX_ELF_FILES] = {NULL, NULL};
int num_files = 0;

/* Function declarations */
void toggle_debug_mode();
void examine_elf_file();
void print_section_names();
void print_symbols();
void print_relocations();
void check_files_for_merge();
void merge_elf_files();
void quit();

/* Menu structure */
typedef struct {
    char *name;
    void (*func)();
} menu_item;

menu_item menu[] = {
    {"Toggle Debug Mode", toggle_debug_mode},
    {"Examine ELF File", examine_elf_file},
    {"Print Section Names", print_section_names},
    {"Print Symbols", print_symbols},
    {"Print Relocations", print_relocations},
    {"Check Files for Merge", check_files_for_merge},
    {"Merge ELF Files", merge_elf_files},
    {"Quit", quit},
    {NULL, NULL}
};

/* Helper function to get data encoding string */
const char* get_data_encoding(unsigned char encoding) {
    switch(encoding) {
        case ELFDATANONE: return "Invalid data encoding";
        case ELFDATA2LSB: return "2's complement, little endian";
        case ELFDATA2MSB: return "2's complement, big endian";
        default: return "Unknown data encoding";
    }
}

/* Toggle debug mode */
void toggle_debug_mode() {
    debug_mode = !debug_mode;
    printf("Debug mode %s\n", debug_mode ? "ON" : "OFF");
}

/* Examine ELF file */
void examine_elf_file() {
    char filename[256];
    int fd;
    struct stat st;
    void *map;
    Elf32_Ehdr *header;
    int index;

    /* Check if we already have 2 files */
    if (num_files >= MAX_ELF_FILES) {
        printf("Error: Maximum number of ELF files (%d) already opened\n", MAX_ELF_FILES);
        return;
    }

    printf("Enter ELF file name: ");
    if (fgets(filename, sizeof(filename), stdin) == NULL) {
        printf("Error reading filename\n");
        return;
    }
    /* Remove newline */
    filename[strcspn(filename, "\n")] = 0;

    /* Open the file */
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Error opening file");
        return;
    }

    /* Get file size */
    if (fstat(fd, &st) < 0) {
        perror("Error getting file size");
        close(fd);
        return;
    }

    /* Map the file */
    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("Error mapping file");
        close(fd);
        return;
    }

    /* Check ELF magic number */
    header = (Elf32_Ehdr *)map;
    if (header->e_ident[EI_MAG0] != ELFMAG0 ||
        header->e_ident[EI_MAG1] != ELFMAG1 ||
        header->e_ident[EI_MAG2] != ELFMAG2 ||
        header->e_ident[EI_MAG3] != ELFMAG3) {
        printf("Error: Not a valid ELF file\n");
        munmap(map, st.st_size);
        close(fd);
        return;
    }

    /* Find available slot */
    index = num_files;
    
    /* Store file info */
    current_fd[index] = fd;
    map_start[index] = map;
    file_size[index] = st.st_size;
    file_name[index] = strdup(filename);
    num_files++;

    /* Print ELF header information */
    printf("\n=== ELF Header Information for: %s ===\n", filename);
    printf("Magic number (bytes 1-3):           %c%c%c\n", 
           header->e_ident[EI_MAG1], 
           header->e_ident[EI_MAG2], 
           header->e_ident[EI_MAG3]);
    printf("Data encoding:                      %s\n", 
           get_data_encoding(header->e_ident[EI_DATA]));
    printf("Entry point address:                0x%x\n", header->e_entry);
    printf("Section header table offset:        %d (bytes into file)\n", header->e_shoff);
    printf("Number of section headers:          %d\n", header->e_shnum);
    printf("Size of section headers:            %d (bytes)\n", header->e_shentsize);
    printf("Program header table offset:        %d (bytes into file)\n", header->e_phoff);
    printf("Number of program headers:          %d\n", header->e_phnum);
    printf("Size of program headers:            %d (bytes)\n", header->e_phentsize);
    printf("\n");
}

/* Helper function to get section type string */
const char* get_section_type(Elf32_Word type) {
    switch(type) {
        case SHT_NULL: return "NULL";
        case SHT_PROGBITS: return "PROGBITS";
        case SHT_SYMTAB: return "SYMTAB";
        case SHT_STRTAB: return "STRTAB";
        case SHT_RELA: return "RELA";
        case SHT_HASH: return "HASH";
        case SHT_DYNAMIC: return "DYNAMIC";
        case SHT_NOTE: return "NOTE";
        case SHT_NOBITS: return "NOBITS";
        case SHT_REL: return "REL";
        case SHT_SHLIB: return "SHLIB";
        case SHT_DYNSYM: return "DYNSYM";
        default: return "UNKNOWN";
    }
}

/* Print section names */
void print_section_names() {
    int i, j;
    Elf32_Ehdr *header;
    Elf32_Shdr *section_header_table;
    Elf32_Shdr *shstrtab_header;
    char *shstrtab;
    
    /* Check if any files are open */
    if (num_files == 0) {
        printf("Error: No ELF files are currently open\n");
        return;
    }

    /* Process each open ELF file */
    for (i = 0; i < num_files; i++) {
        if (map_start[i] == NULL) continue;
        
        header = (Elf32_Ehdr *)map_start[i];
        
        /* Get section header table */
        section_header_table = (Elf32_Shdr *)((char *)map_start[i] + header->e_shoff);
        
        /* Get section header string table */
        shstrtab_header = &section_header_table[header->e_shstrndx];
        shstrtab = (char *)map_start[i] + shstrtab_header->sh_offset;
        
        /* Debug info */
        if (debug_mode) {
            printf("\n[DEBUG] File: %s\n", file_name[i]);
            printf("[DEBUG] e_shoff (section header table offset): %d\n", header->e_shoff);
            printf("[DEBUG] e_shnum (number of sections): %d\n", header->e_shnum);
            printf("[DEBUG] e_shstrndx (section name string table index): %d\n", header->e_shstrndx);
            printf("[DEBUG] shstrtab offset: %d\n", shstrtab_header->sh_offset);
        }
        
        /* Print file header */
        printf("\nFile %s\n", file_name[i]);
        printf("[%-3s] %-20s %-10s %-10s %-10s %s\n", 
               "Nr", "Name", "Addr", "Off", "Size", "Type");
        
        /* Print each section */
        for (j = 0; j < header->e_shnum; j++) {
            Elf32_Shdr *sh = &section_header_table[j];
            char *name = shstrtab + sh->sh_name;
            
            if (debug_mode) {
                printf("[DEBUG] Section %d: sh_name offset = %d\n", j, sh->sh_name);
            }
            
            printf("[%3d] %-20s %08x %08x %08x %s\n",
                   j,
                   name,
                   sh->sh_addr,
                   sh->sh_offset,
                   sh->sh_size,
                   get_section_type(sh->sh_type));
        }
    }
}

/* Helper function to get section name by index */
const char* get_section_name_by_index(Elf32_Ehdr *header, void *map, int index) {
    Elf32_Shdr *section_header_table;
    Elf32_Shdr *shstrtab_header;
    char *shstrtab;
    
    if (index == SHN_UNDEF) return "UND";
    if (index == SHN_ABS) return "ABS";
    if (index == SHN_COMMON) return "COM";
    if (index >= header->e_shnum) return "???";
    
    section_header_table = (Elf32_Shdr *)((char *)map + header->e_shoff);
    shstrtab_header = &section_header_table[header->e_shstrndx];
    shstrtab = (char *)map + shstrtab_header->sh_offset;
    
    return shstrtab + section_header_table[index].sh_name;
}

/* Print symbols */
void print_symbols() {
    int i, j, k;
    Elf32_Ehdr *header;
    Elf32_Shdr *section_header_table;
    Elf32_Shdr *shstrtab_header;
    char *shstrtab;
    
    /* Check if any files are open */
    if (num_files == 0) {
        printf("Error: No ELF files are currently open\n");
        return;
    }

    /* Process each open ELF file */
    for (i = 0; i < num_files; i++) {
        if (map_start[i] == NULL) continue;
        
        header = (Elf32_Ehdr *)map_start[i];
        section_header_table = (Elf32_Shdr *)((char *)map_start[i] + header->e_shoff);
        shstrtab_header = &section_header_table[header->e_shstrndx];
        shstrtab = (char *)map_start[i] + shstrtab_header->sh_offset;
        
        printf("\nFile %s\n", file_name[i]);
        
        /* Find symbol tables */
        int found_symtab = 0;
        for (j = 0; j < header->e_shnum; j++) {
            Elf32_Shdr *sh = &section_header_table[j];
            
            if (sh->sh_type == SHT_SYMTAB || sh->sh_type == SHT_DYNSYM) {
                found_symtab = 1;
                
                /* Get symbol table info */
                Elf32_Sym *symtab = (Elf32_Sym *)((char *)map_start[i] + sh->sh_offset);
                int num_symbols = sh->sh_size / sh->sh_entsize;
                
                /* Get string table for symbol names (sh_link points to it) */
                Elf32_Shdr *strtab_header = &section_header_table[sh->sh_link];
                char *strtab = (char *)map_start[i] + strtab_header->sh_offset;
                
                /* Debug info */
                if (debug_mode) {
                    printf("[DEBUG] Symbol table: %s\n", shstrtab + sh->sh_name);
                    printf("[DEBUG] Symbol table size: %d bytes\n", sh->sh_size);
                    printf("[DEBUG] Number of symbols: %d\n", num_symbols);
                    printf("[DEBUG] String table index: %d\n", sh->sh_link);
                }
                
                /* Print header */
                printf("[%-3s] %-8s %-5s %-20s %s\n", 
                       "Nr", "Value", "Ndx", "Section", "Name");
                
                /* Print each symbol */
                for (k = 0; k < num_symbols; k++) {
                    Elf32_Sym *sym = &symtab[k];
                    char *sym_name = strtab + sym->st_name;
                    const char *section_name = get_section_name_by_index(header, map_start[i], sym->st_shndx);
                    
                    printf("[%3d] %08x %-5d %-20s %s\n",
                           k,
                           sym->st_value,
                           sym->st_shndx,
                           section_name,
                           sym_name);
                }
            }
        }
        
        if (!found_symtab) {
            printf("No symbol table found\n");
        }
    }
}

/* Helper function to get relocation type string and size */
const char* get_rel_type_string(unsigned char type) {
    switch(type) {
        case R_386_NONE: return "R_386_NONE";
        case R_386_32: return "R_386_32";
        case R_386_PC32: return "R_386_PC32";
        case R_386_GOT32: return "R_386_GOT32";
        case R_386_PLT32: return "R_386_PLT32";
        case R_386_COPY: return "R_386_COPY";
        case R_386_GLOB_DAT: return "R_386_GLOB_DAT";
        case R_386_JMP_SLOT: return "R_386_JMP_SLOT";
        case R_386_RELATIVE: return "R_386_RELATIVE";
        case R_386_GOTOFF: return "R_386_GOTOFF";
        case R_386_GOTPC: return "R_386_GOTPC";
        default: return "UNKNOWN";
    }
}

int get_rel_size(unsigned char type) {
    switch(type) {
        case R_386_32:
        case R_386_PC32:
        case R_386_GOT32:
        case R_386_PLT32:
        case R_386_GLOB_DAT:
        case R_386_JMP_SLOT:
        case R_386_RELATIVE:
        case R_386_GOTOFF:
        case R_386_GOTPC:
            return 4;
        default:
            return 0;
    }
}

/* Print relocations */
void print_relocations() {
    int i, j, k;
    Elf32_Ehdr *header;
    Elf32_Shdr *section_header_table;
    Elf32_Shdr *shstrtab_header;
    char *shstrtab;
    
    /* Check if any files are open */
    if (num_files == 0) {
        printf("Error: No ELF files are currently open\n");
        return;
    }

    /* Process each open ELF file */
    for (i = 0; i < num_files; i++) {
        if (map_start[i] == NULL) continue;
        
        header = (Elf32_Ehdr *)map_start[i];
        section_header_table = (Elf32_Shdr *)((char *)map_start[i] + header->e_shoff);
        shstrtab_header = &section_header_table[header->e_shstrndx];
        shstrtab = (char *)map_start[i] + shstrtab_header->sh_offset;
        
        printf("\nFile %s relocations\n", file_name[i]);
        
        /* Find relocation sections */
        int found_rel = 0;
        for (j = 0; j < header->e_shnum; j++) {
            Elf32_Shdr *sh = &section_header_table[j];
            
            if (sh->sh_type == SHT_REL) {
                found_rel = 1;
                
                /* Get relocation table */
                Elf32_Rel *rel_table = (Elf32_Rel *)((char *)map_start[i] + sh->sh_offset);
                int num_rels = sh->sh_size / sh->sh_entsize;
                
                /* Get associated symbol table (sh_link) */
                Elf32_Shdr *symtab_header = &section_header_table[sh->sh_link];
                Elf32_Sym *symtab = (Elf32_Sym *)((char *)map_start[i] + symtab_header->sh_offset);
                
                /* Get string table for symbol names */
                Elf32_Shdr *strtab_header = &section_header_table[symtab_header->sh_link];
                char *strtab = (char *)map_start[i] + strtab_header->sh_offset;
                
                /* Debug info */
                if (debug_mode) {
                    printf("[DEBUG] Relocation section: %s\n", shstrtab + sh->sh_name);
                    printf("[DEBUG] Number of relocations: %d\n", num_rels);
                    printf("[DEBUG] Associated symbol table index: %d\n", sh->sh_link);
                    printf("[DEBUG] Applies to section index: %d\n", sh->sh_info);
                }
                
                /* Print header */
                printf("\nRelocation section '%s' at offset 0x%x contains %d entries:\n",
                       shstrtab + sh->sh_name, sh->sh_offset, num_rels);
                printf("[%-3s] %-10s %-4s %-15s %s\n", 
                       "Nr", "Offset", "Size", "Type", "Symbol");
                
                /* Print each relocation */
                for (k = 0; k < num_rels; k++) {
                    Elf32_Rel *rel = &rel_table[k];
                    unsigned int sym_idx = ELF32_R_SYM(rel->r_info);
                    unsigned char rel_type = ELF32_R_TYPE(rel->r_info);
                    char *sym_name = strtab + symtab[sym_idx].st_name;
                    
                    printf("[%3d] %08x %-4d %-15s %s\n",
                           k,
                           rel->r_offset,
                           get_rel_size(rel_type),
                           get_rel_type_string(rel_type),
                           sym_name);
                }
            }
            else if (sh->sh_type == SHT_RELA) {
                found_rel = 1;
                
                /* Get relocation table with addend */
                Elf32_Rela *rela_table = (Elf32_Rela *)((char *)map_start[i] + sh->sh_offset);
                int num_relas = sh->sh_size / sh->sh_entsize;
                
                /* Get associated symbol table (sh_link) */
                Elf32_Shdr *symtab_header = &section_header_table[sh->sh_link];
                Elf32_Sym *symtab = (Elf32_Sym *)((char *)map_start[i] + symtab_header->sh_offset);
                
                /* Get string table for symbol names */
                Elf32_Shdr *strtab_header = &section_header_table[symtab_header->sh_link];
                char *strtab = (char *)map_start[i] + strtab_header->sh_offset;
                
                /* Print header */
                printf("\nRelocation section '%s' (with addend) contains %d entries:\n",
                       shstrtab + sh->sh_name, num_relas);
                printf("[%-3s] %-10s %-4s %-15s %s\n", 
                       "Nr", "Offset", "Size", "Type", "Symbol");
                
                /* Print each relocation */
                for (k = 0; k < num_relas; k++) {
                    Elf32_Rela *rela = &rela_table[k];
                    unsigned int sym_idx = ELF32_R_SYM(rela->r_info);
                    unsigned char rel_type = ELF32_R_TYPE(rela->r_info);
                    char *sym_name = strtab + symtab[sym_idx].st_name;
                    
                    printf("[%3d] %08x %-4d %-15s %s + %d\n",
                           k,
                           rela->r_offset,
                           get_rel_size(rel_type),
                           get_rel_type_string(rel_type),
                           sym_name,
                           rela->r_addend);
                }
            }
        }
        
        if (!found_rel) {
            printf("No relocations\n");
        }
    }
}

/* Check files for merge - stub */
void check_files_for_merge() {
    printf("not implemented yet\n");
}

/* Merge ELF files - stub */
void merge_elf_files() {
    printf("not implemented yet\n");
}

/* Quit - cleanup and exit */
void quit() {
    int i;
    for (i = 0; i < MAX_ELF_FILES; i++) {
        if (map_start[i] != NULL) {
            munmap(map_start[i], file_size[i]);
            map_start[i] = NULL;
        }
        if (current_fd[i] >= 0) {
            close(current_fd[i]);
            current_fd[i] = -1;
        }
        if (file_name[i] != NULL) {
            free(file_name[i]);
            file_name[i] = NULL;
        }
    }
    printf("Goodbye!\n");
    exit(0);
}

/* Print menu */
void print_menu() {
    int i;
    printf("\nChoose action:\n");
    for (i = 0; menu[i].name != NULL; i++) {
        printf("%d-%s\n", i, menu[i].name);
    }
}

int main(int argc, char *argv[]) {
    int choice;
    int menu_size;
    
    /* Calculate menu size */
    for (menu_size = 0; menu[menu_size].name != NULL; menu_size++);

    while (1) {
        print_menu();
        
        if (scanf("%d", &choice) != 1) {
            /* Clear invalid input */
            while (getchar() != '\n');
            printf("Invalid input\n");
            continue;
        }
        /* Clear the newline from buffer */
        while (getchar() != '\n');

        if (choice < 0 || choice >= menu_size) {
            printf("Invalid choice\n");
            continue;
        }

        menu[choice].func();
    }

    return 0;
}
