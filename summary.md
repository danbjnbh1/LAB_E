# Lab E Summary - Linking ELF Object Files

## What We Did
Implemented **Pass I of the Linker** - a program that reads 2 object files (.o) and merges them into a single relocatable file.

---

## Key Concepts

### ELF File (Executable and Linkable Format)
Standard format for executables in Linux. Contains:
- **ELF Header** - general info about the file
- **Section Header Table** - describes all sections
- **Sections** - the actual data (code, variables, symbols...)

### Important Sections
| Section | Purpose |
|---------|---------|
| `.text` | Program code (instructions) |
| `.data` | Initialized global variables |
| `.rodata` | Read-only data (constant strings) |
| `.symtab` | Symbol table (function/variable names) |
| `.strtab` | Symbol name strings |
| `.shstrtab` | Section name strings |
| `.rel.text` | Relocation table for .text |

### Symbol
A name representing an address - function or variable.
- **Defined** - has value and section index
- **UNDEFINED (UND)** - must be found in another file

### Relocation
Instruction telling the linker where to fix an address in code.
- `R_386_32` - absolute address (32-bit)
- `R_386_PC32` - PC-relative address (for call instructions)

### mmap
System call that maps a file directly to memory - allows accessing file as if it were an array.

---

## Program Menu

```
0. Toggle Debug Mode - turn debug prints on/off
1. Examine ELF File - open file and print header info
2. Print Section Names - print all sections
3. Print Symbols - print symbol table
4. Print Relocations - print relocation table
5. Check Files for Merge - check compatibility before merge
6. Merge ELF Files - merge 2 files into out.ro
7. Quit - cleanup and exit
```

---

## Run Example

```bash
# Compile
make

# Run
./myELF
```

```
Choose action:
0-Toggle Debug Mode
1-Examine ELF File
...
> 1
Enter ELF file name: elfs/F1a.o

=== ELF Header Information for: elfs/F1a.o ===
Magic number (bytes 1-3):           ELF
Entry point address:                0x0
Number of section headers:          8
...

> 1
Enter ELF file name: elfs/F2a.o
...

> 6
Merge completed! Output file: out.ro

> 7
Goodbye!
```

### Verify merge:
```bash
readelf -S out.ro    # check sections are merged
```

---

## Useful Formulas
```
Section header size = e_shentsize (usually 40 bytes)
Section header table offset = e_shoff
Number of sections = e_shnum
Section name = shstrtab[section_header.sh_name]
Symbol name = strtab[symbol.st_name]
Symbol section = section_header_table[symbol.st_shndx]
```
