#include <asm/prctl.h>
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>

#include "psnap.h"
#include "report.h"

#define PAGE_UP(x) (((unsigned long) x + 4095) & (~4095))
#define PAGE_DOWN(x) ((unsigned long) x & (~4095))


static struct snapshot*
parse_snapshot(void* elf)
{
    struct snapshot* snap = malloc(sizeof(struct snapshot));
    Elf_Ehdr* ehdr = (Elf_Ehdr*) elf;
    Elf_Shdr* shdr = (Elf_Shdr*) (elf + ehdr->e_shoff);

    for (size_t i = 0; i < ehdr->e_shnum; i++) {
        switch (shdr[i].sh_type)
        {
        case SHT_PSNAP_REGS:
            report("Found SHT_PSNAP_REGS section: offset=0x%08lx size=%lu",
                   shdr[i].sh_offset, shdr[i].sh_size);

            snap->regs = (struct user_regs_struct*) (elf + shdr[i].sh_offset);
            break;

        case SHT_PSNAP_FPREGS:
            report("Found SHT_PSNAP_FPREGS section: offset=0x%08lx size=%lu",
                   shdr[i].sh_offset, shdr[i].sh_size);

            snap->fpregs = (struct user_fpregs_struct*) (elf + shdr[i].sh_offset);
            break;

        case SHT_PSNAP_FDINFO:
            report("Found SHT_PSNAP_FPREGS section: offset=0x%08lx size=%lu",
                   shdr[i].sh_offset, shdr[i].sh_size);

            snap->fdinfo = (struct fdinfo*) (elf + shdr[i].sh_offset);
            snap->nfdinfo = shdr[i].sh_size / shdr[i].sh_entsize;
            break;

        default:
            break;
        }
    }

    return snap;
}


static int
open_file_handlers(struct fdinfo* fdinfo, size_t nfdinfo)
{
    for (size_t i = 0; i < nfdinfo; i++) {
        int fd = 0;

        if (fdinfo[i].fd < 3)
            continue;

        if (strstr(fdinfo[i].path, "socket") ||
            strstr(fdinfo[i].path, "anon_inode") ||
            strstr(fdinfo[i].path, "pipe")) {
            fd = open("/dev/null", fdinfo[i].flags);
        } else {
            fd = open(fdinfo[i].path, fdinfo[i].flags);
        }

        if (fd < 0) {
            report_error("can't open '%s': %s", fdinfo[i].path,
                         strerror(errno));
            return -1;
        }

        if (fdinfo[i].pos != 0 && lseek(fd, fdinfo[i].pos, SEEK_SET) < 0) {
            report_error("can't seek in '%s': %s", fdinfo[i].path,
                         strerror(errno));
            close(fd);
            return -1;
        }

        if (dup2(fd, fdinfo[i].fd) < 0) {
            report_error("can't set file descriptor %d for '%s'", fdinfo[i].fd,
                         fdinfo[i].path);
            return -1;
        }

        report("Opened file handler: path=%s pos=%lu", fdinfo[i].path,
               fdinfo[i].pos);
    }

    return 0;
}


static uint8_t*
generate_munmap(uint8_t* ptr, size_t addr, size_t len)
{
    *ptr++ = 0x48;
    *ptr++ = 0xc7;
    *ptr++ = 0xc0;
    *(uint32_t*) ptr = (uint32_t) 0x0b;
    ptr += sizeof(uint32_t);

    *ptr++ = 0x48;
    *ptr++ = 0xbf;
    *(uint64_t*) ptr = (uint64_t) addr;
    ptr += sizeof(uint64_t);

    *ptr++ = 0x48;
    *ptr++ = 0xbe;
    *(uint64_t*) ptr = (uint64_t) len;
    ptr += sizeof(uint64_t);

    *ptr++ = 0x0f;
    *ptr++ = 0x05;

    return ptr;
}


static uint8_t*
generate_munmap_current_executable(uint8_t* ptr)
{
    uint8_t* ret = NULL;

    FILE* stat_file = NULL;
    char stat_path[64] = { 0 };

    FILE* maps_file = NULL;
    char maps_path[64] = { 0 };

    size_t bottom = 0;
    size_t top = 0;
    char perms[5] = { 0 };
    char buf[256] = { 0 };
    char exe[256] = { 0 };

    snprintf(stat_path, 64, "/proc/self/stat");
    stat_file = fopen(stat_path, "r");
    if (stat_file == NULL) {
        report_error("can't open '%s': %s", stat_path, strerror(errno));
        goto cleanup;
    }

    if (fscanf(stat_file, "%*d %s", exe) == EOF) {
        report_error("can't read '%s': %s", stat_path, strerror(errno));
        goto cleanup;
    }

    exe[strlen(exe) - 1] = '\0';

    snprintf(maps_path, 64, "/proc/self/maps");
    maps_file = fopen(maps_path, "r");
    if (maps_file == NULL) {
        report_error("can't open '%s': %s", maps_path, strerror(errno));
        goto cleanup;
    }

    while (fscanf(maps_file, "%lx-%lx %s %[^\n]\n", &bottom, &top, perms,
                  buf) != EOF) {
        if (strstr(buf, exe + 1) == NULL)
            continue;

        ptr = generate_munmap(ptr, bottom, top - bottom);
        report("Unmapped region: base=0x%08lx size=%lu", bottom, top - bottom);
    }

    if (ferror(maps_file)) {
        report_error("can't read '%s': %s", maps_path, strerror(errno));
        goto cleanup;
    }

    ret = ptr;

 cleanup:
    if (stat_file != NULL)
        fclose(stat_file);

    if (maps_file != NULL)
        fclose(maps_file);

    return ret;
}


static uint8_t*
generate_mmap(uint8_t* ptr, size_t addr, size_t len, int prot, int flags)
{
    *ptr++ = 0x48;
    *ptr++ = 0xc7;
    *ptr++ = 0xc0;
    *(uint32_t*) ptr = (uint32_t) 0x09;
    ptr += sizeof(uint32_t);

    *ptr++ = 0x48;
    *ptr++ = 0xbf;
    *(uint64_t*) ptr = (uint64_t) addr;
    ptr += sizeof(uint64_t);

    *ptr++ = 0x48;
    *ptr++ = 0xbe;
    *(uint64_t*) ptr = (uint64_t) len;
    ptr += sizeof(uint64_t);

    *ptr++ = 0x48;
    *ptr++ = 0xc7;
    *ptr++ = 0xc2;
    *(uint32_t*) ptr = (uint32_t) prot;
    ptr += sizeof(uint32_t);

    *ptr++ = 0x49;
    *ptr++ = 0xc7;
    *ptr++ = 0xc2;
    *(uint32_t*) ptr = (uint32_t) flags;
    ptr += sizeof(uint32_t);

    *ptr++ = 0x49;
    *ptr++ = 0xc7;
    *ptr++ = 0xc0;
    *(uint32_t*) ptr = (uint32_t) 0xffff;
    ptr += sizeof(uint32_t);

    *ptr++ = 0x49;
    *ptr++ = 0xc7;
    *ptr++ = 0xc1;
    *(uint32_t*) ptr = (uint32_t) 0;
    ptr += sizeof(uint32_t);

    *ptr++ = 0x0f;
    *ptr++ = 0x05;

    return ptr;
}

const size_t mmap_size = 21 + 5 * sizeof(uint32_t) + 2 * sizeof(uint64_t);


static uint8_t*
generate_memcpy(uint8_t* ptr, size_t dest, size_t src, size_t len)
{
    *ptr++ = 0x48;
    *ptr++ = 0xbe;
    *(uint64_t*) ptr = (uint64_t) src;
    ptr += sizeof(uint64_t);

    *ptr++ = 0x48;
    *ptr++ = 0xbf;
    *(uint64_t*) ptr = (uint64_t) dest;
    ptr += sizeof(uint64_t);

    *ptr++ = 0x48;
    *ptr++ = 0xb9;
    *(uint64_t*) ptr = (uint64_t) len;
    ptr += sizeof(uint64_t);

    *ptr++ = 0xf3;
    *ptr++ = 0xa4;

    return ptr;
}

const size_t memcpy_size = 8 + 3 * sizeof(uint64_t);


static uint8_t*
generate_mprotect(uint8_t* ptr, size_t addr, size_t len, int prot)
{
    *ptr++ = 0x48;
    *ptr++ = 0xc7;
    *ptr++ = 0xc0;
    *(uint32_t*) ptr = (uint32_t) 0x0a;
    ptr += sizeof(uint32_t);

    *ptr++ = 0x48;
    *ptr++ = 0xbf;
    *(uint64_t*) ptr = (uint64_t) addr;
    ptr += sizeof(uint64_t);

    *ptr++ = 0x48;
    *ptr++ = 0xbe;
    *(uint64_t*) ptr = (uint64_t) len;
    ptr += sizeof(uint64_t);

    *ptr++ = 0x48;
    *ptr++ = 0xc7;
    *ptr++ = 0xc2;
    *(uint32_t*) ptr = (uint32_t) prot;
    ptr += sizeof(uint32_t);

    *ptr++ = 0x0f;
    *ptr++ = 0x05;

    return ptr;
}

const size_t mprotect_size = 12 + 2 * sizeof(uint32_t) + 2 * sizeof(uint64_t);


static void*
generate_jumpbuf(void* elf, struct snapshot* snap)
{
    void* jumpbuf = NULL;
    uint8_t* tmp = NULL;

    Elf_Ehdr* ehdr = (Elf_Ehdr*) elf;
    Elf_Phdr* phdr = (Elf_Phdr*) (elf + ehdr->e_phoff);

    size_t per_phdr_size = mmap_size + memcpy_size + mprotect_size;
    jumpbuf = mmap((void*) 0x1000000,
                   PAGE_UP(PAGE_SIZE + per_phdr_size * ehdr->e_phnum),
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (jumpbuf == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }

    tmp = (uint8_t*) jumpbuf;

    if ((tmp = generate_munmap_current_executable(tmp)) == NULL)
        return NULL;

    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        int prot = 0;
        size_t load_addr = 0;
        size_t len = 0;

        if (phdr[i].p_type != PT_LOAD)
            continue;

        if (phdr[i].p_vaddr == 0xffffffffff600000)
            continue;

        load_addr = PAGE_DOWN(phdr[i].p_vaddr);
        len = PAGE_UP(phdr[i].p_memsz + (phdr[i].p_vaddr % PAGE_SIZE));
        tmp = generate_mmap(tmp, load_addr, len,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS);
        tmp = generate_memcpy(tmp, phdr[i].p_vaddr,
                              (size_t) (elf + phdr[i].p_offset),
                              phdr[i].p_filesz);

        if (phdr[i].p_flags & PF_R)
            prot |= PROT_READ;
        if (phdr[i].p_flags & PF_W)
            prot |= PROT_WRITE;
        if (phdr[i].p_flags & PF_X)
            prot |= PROT_EXEC;

        tmp = generate_mprotect(tmp, load_addr, len, prot);

        report("Mapped segment: addr=0x%08lx len=%lu prot=%d flags=%d",
               phdr[i].p_vaddr, phdr[i].p_memsz, prot,
               MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS);
    }

    /*
     * Recover fpregs
     * 48 bf 00 b0 ff f7 ff    movabs $0x7ffff7ffb000,%rdi
     * 7f 00 00 
     * d9 27                   fldenv (%rdi)
     */
    *tmp++ = 0x48;
    *tmp++ = 0xbf;
    *(uint64_t*) tmp = (uint64_t) snap->fpregs;
    tmp += sizeof(uint64_t);
    *tmp++ = 0xd9;
    *tmp++ = 0x27;

    /*
     * Recover stack pointer
     * 48 bc d8 8b 91 48 fe    movabs $0x7ffe48918bd8,%rsp
     * 7f 00 00
     */
    *tmp++ = 0x48;
    *tmp++ = 0xbc;
    *(uint64_t*) tmp = snap->regs->rsp;
    tmp += sizeof(uint64_t);

    /*
     * Recover eflags/rflags
     * 48 b8 02 02 01 00 00    movabs $0x10202,%rax
     * 00 00 00
     * 50                      push   %rax
     * 9d                      popf
     */
    *tmp++ = 0x48;
    *tmp++ = 0xb8;
    *(uint64_t*) tmp = (uint64_t) snap->regs->eflags;
    tmp += sizeof(uint64_t);
    *tmp++ = 0x50;
    *tmp++ = 0x9d;

    /*
     * Store instruction pointer at top of the stack
     * 48 b8 d2 7f 41 46 67    movabs $0x7f6746417fd2,%rax
     * 7f 00 00
     * 50                      push   %rax
     */
    *tmp++ = 0x48;
    *tmp++ = 0xb8;
    *(uint64_t*) tmp = (uint64_t) snap->regs->rip;
    tmp += sizeof(uint64_t);
    *tmp++ = 0x50;

    /*
     * Recover fs base
     * 48 b8 d2 7f 41 46 67    movabs $0x7f4e32296a7c,%rax
     * 50                      push   %rax
     * 48 c7 c0 9e 00 00 00    mov    $0x9e,%rax
     * 48 c7 c7 02 10 00 00    mov    $0x1002,%rdi
     * 48 be 40 1a c8 32 4e    movabs $0x7f4e32c81a40,%rsi
     * 7f 00 00
     * syscall
     */
    *tmp++ = 0x48;
    *tmp++ = 0xc7;
    *tmp++ = 0xc0;
    *(uint32_t*) tmp = (uint32_t) 0x9e;
    tmp += sizeof(uint32_t);
    *tmp++ = 0x48;
    *tmp++ = 0xc7;
    *tmp++ = 0xc7;
    *(uint32_t*) tmp = (uint32_t) ARCH_SET_FS;
    tmp += sizeof(uint32_t);
    *tmp++ = 0x48;
    *tmp++ = 0xbe;
    *(uint64_t*) tmp = (uint64_t) snap->regs->fs;
    tmp += sizeof(uint64_t);
    *tmp++ = 0x0f;
    *tmp++ = 0x05;

    /*
     * Recover regs
     * 48 b8 00 fe ff ff ff    movabs $0xfffffffffffffe00,%rax
     * ff ff ff
     */
    *tmp++ = 0x48;
    *tmp++ = 0xb8;
    *(uint64_t*) tmp = (uint64_t) snap->regs->rax;
    tmp += sizeof(uint64_t);

    *tmp++ = 0x48;
    *tmp++ = 0xbb;
    *(uint64_t*) tmp = (uint64_t) snap->regs->rbx;
    tmp += sizeof(uint64_t);

    *tmp++ = 0x48;
    *tmp++ = 0xb9;
    *(uint64_t*) tmp = (uint64_t) snap->regs->rcx;
    tmp += sizeof(uint64_t);

    *tmp++ = 0x48;
    *tmp++ = 0xba;
    *(uint64_t*) tmp = (uint64_t) snap->regs->rdx;
    tmp += sizeof(uint64_t);

    *tmp++ = 0x48;
    *tmp++ = 0xbd;
    *(uint64_t*) tmp = (uint64_t) snap->regs->rbp;
    tmp += sizeof(uint64_t);

    *tmp++ = 0x48;
    *tmp++ = 0xbe;
    *(uint64_t*) tmp = (uint64_t) snap->regs->rsi;
    tmp += sizeof(uint64_t);

    *tmp++ = 0x48;
    *tmp++ = 0xbf;
    *(uint64_t*) tmp = (uint64_t) snap->regs->rdi;
    tmp += sizeof(uint64_t);

    *tmp++ = 0x49;
    *tmp++ = 0xb8;
    *(uint64_t*) tmp = (uint64_t) snap->regs->r8;
    tmp += sizeof(uint64_t);

    *tmp++ = 0x49;
    *tmp++ = 0xb9;
    *(uint64_t*) tmp = (uint64_t) snap->regs->r9;
    tmp += sizeof(uint64_t);

    *tmp++ = 0x49;
    *tmp++ = 0xba;
    *(uint64_t*) tmp = (uint64_t) snap->regs->r10;
    tmp += sizeof(uint64_t);

    *tmp++ = 0x49;
    *tmp++ = 0xbb;
    *(uint64_t*) tmp = (uint64_t) snap->regs->r11;
    tmp += sizeof(uint64_t);

    *tmp++ = 0x49;
    *tmp++ = 0xbc;
    *(uint64_t*) tmp = (uint64_t) snap->regs->r12;
    tmp += sizeof(uint64_t);

    *tmp++ = 0x49;
    *tmp++ = 0xbd;
    *(uint64_t*) tmp = (uint64_t) snap->regs->r13;
    tmp += sizeof(uint64_t);

    *tmp++ = 0x49;
    *tmp++ = 0xbe;
    *(uint64_t*) tmp = (uint64_t) snap->regs->r14;
    tmp += sizeof(uint64_t);

    *tmp++ = 0x49;
    *tmp++ = 0xbf;
    *(uint64_t*) tmp = (uint64_t) snap->regs->r15;
    tmp += sizeof(uint64_t);

    /*
     * Recover instruction pointer from top of the stack
     * c3                      ret
     */
    *tmp++ = 0xc3;

    report("Allocated jumpbuf: addr=0x%08lx size=%lu rip=0x%08lx rsp=0x%08lx",
           (size_t) jumpbuf, (size_t) tmp - (size_t) jumpbuf, snap->regs->rip,
           snap->regs->rsp);

    return jumpbuf;
}


int
main(int argc, char* argv[])
{
    int ret = EXIT_FAILURE;

    int fd = -1;
    void* elf = NULL;
    struct stat st = { 0 };

    struct snapshot* snap = NULL;
    void (*jump)(void);

    set_program_name(argv[0]);

    fd = open(argv[1], O_RDONLY, S_IRWXU);
    if (fd == -1) {
        perror("open");
        goto cleanup;
    }
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        goto cleanup;
    }

    elf = mmap((void*) 0x3000000, st.st_size, PROT_READ,
               MAP_PRIVATE | MAP_FIXED, fd, 0);
    if (elf == MAP_FAILED) {
        perror("mmap");
        goto cleanup;
    }

    report("Allocated snapshot: addr=0x%lx size=%lu", (size_t) elf,
           st.st_size);

    snap = parse_snapshot(elf);

    if (open_file_handlers(snap->fdinfo, snap->nfdinfo) < 0)
        goto cleanup;

    if ((jump = generate_jumpbuf(elf, snap)) == NULL)
        goto cleanup;

    jump();

    ret = EXIT_SUCCESS;

 cleanup:
    munmap(elf, st.st_size);

    return ret;
}
