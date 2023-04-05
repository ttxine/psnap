#ifndef PSNAP_H
#define PSNAP_H

#include <elf.h>
#include <sys/user.h>

#define SHT_PSNAP_REGS SHT_LOUSER
#define SHT_PSNAP_FPREGS SHT_LOUSER + 1
#define SHT_PSNAP_MAP SHT_LOUSER + 2
#define SHT_PSNAP_FDINFO SHT_LOUSER + 3

#ifdef __x86_64__
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Shdr Elf_Shdr;
#endif /* __x86_64__ */

#define FDINFO_MAX_PATH_SIZE 256

struct fdinfo
{
    char path[FDINFO_MAX_PATH_SIZE];
    int fd;
    unsigned int flags;
    size_t pos;
};


struct snapshot
{
    struct fdinfo* fdinfo;
    size_t nfdinfo;
    struct user_regs_struct* regs;
    struct user_fpregs_struct* fpregs;
};


#endif  /* PSNAP_H */
