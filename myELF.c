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

/* Print section names - stub */
void print_section_names() {
    printf("not implemented yet\n");
}

/* Print symbols - stub */
void print_symbols() {
    printf("not implemented yet\n");
}

/* Print relocations - stub */
void print_relocations() {
    printf("not implemented yet\n");
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
