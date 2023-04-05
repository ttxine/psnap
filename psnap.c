#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <asm/prctl.h>
#include <sys/prctl.h>

#include "psnap.h"
#include "report.h"

#define MT_ANON 0
#define MT_SHLIB 1
#define MT_HEAP 2
#define MT_STACK 3
#define MT_VDSO 4
#define MT_VSYSCALL 5
#define MT_ELF 6
#define MT_PADDING 7
#define MT_VVAR 8


struct
{
    pid_t pid;
    char* path;
    int debug;
} opts;


/* Represents mapped memory region */
struct mapping
{
    size_t base;
    size_t size;
    int type;
    int flags;
};


struct process
{
    struct mapping* maps;
    size_t nmaps;
    struct snapshot* snap;
};


static bool
process_exists(pid_t pid)
{
    errno = 0;
    kill(pid, 0);
    return errno != ESRCH;
}


/*
 * Returns process maps and fills "len" with map count on success,
 * otherwise returns NULL.
 * The returned data must be freed by the caller.
 */
static struct mapping*
get_process_maps(size_t* len)
{
    FILE* stat_file = NULL;
    char stat_path[64] = { 0 };

    FILE* maps_file = NULL;
    char maps_path[64] = { 0 };

    size_t bottom = 0;
    size_t top = 0;
    char perms[5] = { 0 };
    char buf[256] = { 0 };
    char exe[256] = { 0 };

    struct mapping* maps = NULL;
    size_t nmaps = 0;

    snprintf(stat_path, 64, "/proc/%d/stat", opts.pid);
    stat_file = fopen(stat_path, "r");
    if (stat_file == NULL) {
        report_error("can't open '%s': %s", stat_path, strerror(errno));
        goto error;
    }

    if (fscanf(stat_file, "%*d %s", exe) == EOF) {
        report_error("can't read '%s': %s", stat_path, strerror(errno));
        goto error;
    }

    exe[strlen(exe) - 1] = '\0';

    snprintf(maps_path, 64, "/proc/%d/maps", opts.pid);
    maps_file = fopen(maps_path, "r");
    if (maps_file == NULL) {
        report_error("can't open '%s': %s", maps_path, strerror(errno));
        goto error;
    }

    while (fscanf(maps_file, "%lx-%lx %s %[^\n]\n", &bottom, &top, perms,
                  buf) != EOF) {
        maps = realloc(maps, sizeof(struct mapping) * (nmaps + 1));
        if (maps == NULL) {
            report_error("can't allocate memory for process maps: %s",
                         strerror(errno));
            goto error;
        }

        if (strncmp(perms, "---p", 4) == 0) {
            maps[nmaps].type = MT_PADDING;
        } else if (strstr(buf, exe + 1) != NULL) {
            maps[nmaps].type = MT_ELF;
        } else if (strstr(buf, "[heap]") != NULL) {
            maps[nmaps].type = MT_HEAP;
        } else if (strstr(buf, "[stack]") != NULL) {
            maps[nmaps].type = MT_STACK;
        } else if (strstr(buf, "[vdso]") != NULL) {
            maps[nmaps].type = MT_VDSO;
        } else if (strstr(buf, "[vsyscall]") != NULL) {
            maps[nmaps].type = MT_VSYSCALL;
        } else if (strstr(buf, "[vvar]") != NULL) {
            maps[nmaps].type = MT_VVAR;
        } else if (strstr(buf, ".so") != NULL) {
            maps[nmaps].type = MT_SHLIB;
        } else {
            maps[nmaps].type = MT_ANON;
        }

        maps[nmaps].base = bottom;
        maps[nmaps].size = top - bottom;

        if (perms[0] == 'r')
            maps[nmaps].flags |= PF_R;
        if (perms[1] == 'w')
            maps[nmaps].flags |= PF_W;
        if (perms[2] == 'x')
            maps[nmaps].flags |= PF_X;

        if (opts.debug) {
            report("Found process map: base=0x%08lx size=%lu type=%d flags=%d",
                   maps[nmaps].base, maps[nmaps].size, maps[nmaps].type,
                   maps[nmaps].flags);
        }

        nmaps++;
    }

    if (ferror(maps_file)) {
        report_error("can't read '%s': %s", maps_path, strerror(errno));
        goto error;
    }

    fclose(stat_file);
    fclose(maps_file);

    *len = nmaps;
    return maps;

 error:
    if (stat_file != NULL)
        fclose(stat_file);

    if (maps_file != NULL)
        fclose(maps_file);

    free(maps);
    return NULL;
}


static unsigned int
parse_fdinfo_flags(unsigned int flags)
{
    unsigned int ret = flags & 10;
    size_t degree = 8;

    while ((flags /= 10) != 0) {
        ret += (flags % 10) * degree;
        degree *= 8;
    }

    return ret;
}


/*
 * Returns process fdinfo and fills "len" with fdinfo count on success,
 * otherwise returns NULL.
 * The returned data must be freed by the caller.
 */
static struct fdinfo*
get_process_fdinfo(size_t* len)
{
    DIR* fdinfo_dir = NULL;
    char fdinfo_path[64] = { 0 };
    struct dirent* fdinfo_dir_entry = NULL;

    struct fdinfo* fdinfo = NULL;
    size_t nfdinfo = 0;

    snprintf(fdinfo_path, 64, "/proc/%d/fdinfo", opts.pid);
    fdinfo_dir = opendir(fdinfo_path);
    if (fdinfo_dir == NULL) {
        report_error("can't open '%s': %s", fdinfo_path, strerror(errno));
        goto error;
    }

    errno = 0;
    while ((fdinfo_dir_entry = readdir(fdinfo_dir)) != NULL) {
        char fd_dir_entry_path[64] = { 0 };
        char link_path[FDINFO_MAX_PATH_SIZE] = { 0 };
        size_t link_path_len = 0;

        FILE* fdinfo_file = NULL;
        char fdinfo_file_path[64] = { 0 };

        unsigned int raw_flags = 0;

        if (fdinfo_dir_entry->d_name[0] == '.')
            continue;

        snprintf(fd_dir_entry_path, 64, "/proc/%d/fd/%d", opts.pid,
                 atoi(fdinfo_dir_entry->d_name));
        link_path_len = readlink(fd_dir_entry_path, link_path,
                                 FDINFO_MAX_PATH_SIZE);
        if (link_path_len == -1) {
            report_error("can't read link of '%s': %s", fd_dir_entry_path,
                         strerror(errno));
            goto error;
        }

        fdinfo = realloc(fdinfo, sizeof(struct fdinfo) * (nfdinfo + 1));
        if (fdinfo == NULL) {
            report_error("can't allocate memory for file descriptor information: %s",
                         strerror(errno));
            return NULL;
        }

        memset(fdinfo[nfdinfo].path, 0, FDINFO_MAX_PATH_SIZE);
        memcpy(fdinfo[nfdinfo].path, link_path, link_path_len);
        fdinfo[nfdinfo].fd = atoi(fdinfo_dir_entry->d_name);

        snprintf(fdinfo_file_path, 64, "/proc/%d/fdinfo/%d", opts.pid,
                 fdinfo[nfdinfo].fd);
        fdinfo_file = fopen(fdinfo_file_path, "r");
        if (fdinfo_file == NULL) {
            report_error("can't open '%s': %s", fdinfo_path, strerror(errno));
            goto error;
        }

        if (fscanf(fdinfo_file, "%*s %lu\n", &fdinfo[nfdinfo].pos) == EOF ||
            fscanf(fdinfo_file, "%*s %d\n", &raw_flags) == EOF) {
            report_error("can't read '%s': %s", fdinfo_file_path,
                         strerror(errno));
            fclose(fdinfo_file);
            goto error;
        }

        fdinfo[nfdinfo].flags = parse_fdinfo_flags(raw_flags);

        nfdinfo++;
        errno = 0;

        if (fdinfo_file != NULL)
            fclose(fdinfo_file);
    }

    if (errno != 0) {
        report_error("can't read '%s': %s", fdinfo_dir, strerror(errno));
        goto error;
    }

    *len = nfdinfo;

    if (fdinfo_dir != NULL)
        closedir(fdinfo_dir);

    return fdinfo;

 error:
    if (fdinfo_dir != NULL)
        closedir(fdinfo_dir);

    free(fdinfo);
    return NULL;
}


static int
attach_to_process()
{
    if ((ptrace(PTRACE_ATTACH, opts.pid, 0, 0)) < 0) {
        report_error("can't attach to process: %s", strerror(errno));
        return -1;
    }

	waitpid(opts.pid, NULL, WUNTRACED);

    if (opts.debug)
        report("Attached to process: pid=%d", opts.pid);

    return 0;
}


static int
detach_from_process()
{
    if (ptrace(PTRACE_DETACH, opts.pid, 0, 0) < 0) {
        report_error("can't detach from process: %s", strerror(errno));
        return -1;
    }

    if (opts.debug)
        report("Detached from process: pid=%d", opts.pid);

    return 0;
}


/*
 * Copy "len" bytes of "src" to "dest".
 * To read process memory you need to attach to the process first. See
 * "attach_to_process()".
 * Returns 0 on success, -1 on failure.
 */
static int
copy_process_memory(void* dest, void* src, size_t len)
{
    size_t nread = 0;
    errno = 0;

    for (size_t i = 0; i < len / sizeof(size_t); i++) {
        size_t word = ptrace(PT_READ_D, opts.pid, src + i * sizeof(size_t), 0);

        if (word == -1 && errno != 0) {
            report_error("can't read process memory at address 0x%08lx: %s",
                         (size_t) (src + i * sizeof(size_t)), strerror(errno));
            return -1;
        }

        memcpy(dest + i * sizeof(size_t), &word, sizeof(size_t));
        nread += sizeof(size_t);
    }

    if (nread < len) {
        size_t word = ptrace(PT_READ_D, opts.pid, src + nread, 0);

        if (word == -1 && errno != 0) {
            report_error("can't read process memory at address 0x%08lx: %s",
                         (size_t) (src + nread), strerror(errno));
            return -1;
        }

        memcpy(dest + nread, &word, len - nread);
    }

    return 0;
}


/*
 * Save process "maps" into ELF file as PT_LOAD segments.
 * To make process snapshot you need to attach to the process first. See
 * "attach_to_process()".
 * Returns 0 on success, -1 on failure.
 */
static int
make_process_snapshot(const struct mapping* maps, size_t nmaps)
{
    int ret = -1;

    int fd = -1;
    void* buf = NULL;

    Elf_Ehdr ehdr = { 0 };
    Elf_Phdr* phdr = NULL;
    size_t phind = 0;

    size_t offset = 0;

    if ((fd = open(opts.path, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU)) < 0) {
        report_error("can't open '%s': %s", opts.path, strerror(errno));
        goto cleanup;
    }

    phdr = calloc(sizeof(Elf_Phdr), nmaps);
    if (phdr == NULL) {
        report_error("can't allocate memory for program headers");
        goto cleanup;
    }

    /* Write heap, stack, shared libraries, etc. */
    for (size_t i = 0; i < nmaps; i++) {
        offset = (offset + 0x1000 - 1) & ~(0x1000 - 1);

        phdr[phind].p_type = PT_LOAD;
        phdr[phind].p_vaddr = maps[i].base;
        phdr[phind].p_paddr = maps[i].base;
        phdr[phind].p_offset = offset;
        phdr[phind].p_filesz = maps[i].size;
        phdr[phind].p_memsz = maps[i].size;
        phdr[phind].p_flags = maps[i].flags;
        phdr[phind].p_align = 0x1000;

        if ((buf = realloc(buf, maps[i].size)) == NULL) {
            report_error("can't allocate memory for PT_LOAD segment");
            goto cleanup;
        }

        memset(buf, 0, maps[i].size);
        copy_process_memory(buf, (void*) maps[i].base,
                            maps[i].size);

        if (ftruncate(fd, phdr[phind].p_offset) < 0) {
            report_error("can't truncate '%s': %s", opts.path,
                         strerror(errno));
            goto cleanup;
        }
        if (lseek(fd, phdr[phind].p_offset, SEEK_SET) < 0) {
            report_error("can't seek in '%s': %s", opts.path,
                         strerror(errno));
            goto cleanup;
        }
        if (write(fd, buf, maps[i].size) < 0) {
            report_error("can't write to '%s': %s", opts.path,
                         strerror(errno));
            goto cleanup;
        }

        if (opts.debug) {
            report("Written PT_LOAD segment: vaddr=0x%08lx offset=0x%08lx memsz=%lu flags=%d",
                   phdr[phind].p_vaddr, phdr[phind].p_offset,
                   phdr[phind].p_memsz, phdr[phind].p_flags);
        }

        if (offset == 0)
            memcpy(&ehdr, buf, sizeof(Elf_Ehdr));

        offset += maps[i].size;
        phind++;
    }

    ehdr.e_phnum = phind;

    /* Write new program headers to the end of file */
    if (write(fd, phdr, sizeof(Elf_Phdr) * ehdr.e_phnum) < 0) {
        report_error("can't write to '%s': %s", opts.path,
                        strerror(errno));
        goto cleanup;
    }

    /* Update ELF header */
    ehdr.e_phoff = offset;
    if (lseek(fd, 0, SEEK_SET) < 0) {
        report_error("can't seek in '%s': %s", opts.path, strerror(errno));
        goto cleanup;
    }
    if (write(fd, &ehdr, sizeof(Elf_Ehdr)) < 0) {
        report_error("can't write to '%s': %s", opts.path,
                        strerror(errno));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (fd != -1)
        close(fd);

    if (ret == -1)
        unlink(opts.path);

    free(buf);
    free(phdr);
    return ret;
}


/*
 * To get process regs you need to attach to the process first. See
 * "attach_to_process()".
 * Returns 0 on success, -1 on failure.
 */
static struct user_regs_struct*
get_process_regs()
{
    struct user_regs_struct* regs = malloc(sizeof(struct user_regs_struct));

    if (regs == NULL) {
        report_error("can't allocate memory for regs: %s", strerror(errno));
        goto error;
    }

    if (ptrace(PTRACE_GETREGS, opts.pid, NULL, regs) < 0) {
        report_error("can't get registers: %s", strerror(errno));
        goto error;
    }

    /* 
     * For fs, we need to make a special request because its base
     * address is stored in fs:0.
     */
    if (ptrace(PT_ARCH_PRCTL, opts.pid, &regs->fs, ARCH_GET_FS) < 0) {
        report_error("can't get fs base: %s", strerror(errno));
        goto error;
    }

    return regs;

 error:
    free(regs);

    return NULL;
}


/*
 * To get process fpregs you need to attach to the process first. See
 * "attach_to_process()".
 * Returns 0 on success, -1 on failure.
 */
static struct user_fpregs_struct*
get_process_fpregs()
{
    struct user_fpregs_struct* fpregs = NULL;

    fpregs = malloc(sizeof(struct user_fpregs_struct));
    if (fpregs == NULL) {
        report_error("can't allocate memory for fpregs: %s", strerror(errno));
        goto error;
    }

    if (ptrace(PTRACE_GETFPREGS, opts.pid, NULL, fpregs) < 0) {
        report_error("can't get floating point registers: %s",
                     strerror(errno));
        goto error;
    }

    return fpregs;

 error:
    free(fpregs);

    return NULL;
}


/*
 * To get process information you need to attach to the process first.
 * See "attach_to_process()".
 * Returns 0 on success, -1 on failure.
 */
static struct process*
get_processrmation()
{
    struct process* proc = malloc(sizeof(struct process));
    proc->snap = malloc(sizeof(struct snapshot));

    if (proc->snap == NULL) {
        report_error("can't allocate memory for snapshot: %s",
                     strerror(errno));
        return NULL;
    }

    if ((proc->maps = get_process_maps(&proc->nmaps)) == NULL)
        goto error;

    proc->snap->fdinfo = get_process_fdinfo(&proc->snap->nfdinfo);
    if (proc->snap->fdinfo == NULL)
        goto error;

    if ((proc->snap->regs = get_process_regs()) == NULL)
        goto error;

    if ((proc->snap->fpregs = get_process_fpregs()) == NULL)
        goto error;

    return proc;

 error:
    if (proc) {
        free(proc->maps);

        if (proc->snap) {
            free(proc->snap->fdinfo);
            free(proc->snap->regs);
            free(proc->snap->fpregs);
        }

        free(proc->snap);
    }

    free(proc);
    return NULL;
}


/* Append "shdr" with new section header. */
static Elf_Shdr*
add_section_header(Elf_Shdr* shdr, Elf_Ehdr* ehdr, uint32_t name,
                   uint32_t type, size_t addr, size_t offset, size_t size,
                   size_t flags, uint32_t link, uint32_t info,
                   size_t addralign, size_t entsize)
{
    size_t shind = ehdr->e_shnum;
    size_t shnum = ehdr->e_shnum + 1;

    shdr = realloc(shdr, ehdr->e_shentsize * shnum);
    if (shdr == NULL) {
        report_error("can't allocate memory for section headers: %s",
                     strerror(errno));
        return NULL;
    }

    shdr[shind].sh_name = name;
    shdr[shind].sh_type = type;
    shdr[shind].sh_addr = addr;
    shdr[shind].sh_offset = offset;
    shdr[shind].sh_size = size;
    shdr[shind].sh_flags = flags;
    shdr[shind].sh_link = link;
    shdr[shind].sh_info = info;
    shdr[shind].sh_addralign = addralign;
    shdr[shind].sh_entsize = entsize;

    ehdr->e_shnum = shnum;
    return shdr;
}


/*
 * Returns "name" position in "shstr" on success, 0 if "name" is not
 * found.
 */
static uint32_t
get_section_name(const char* name, const char* shstr, uint32_t size)
{
    for (uint32_t pos = 0; pos < size; pos += strlen(&shstr[pos]) + 1) {
        if(strcmp(name, &shstr[pos]) == 0)
            return pos;
    }

    return 0;
}


/* Returns 0 on success, -1 on failure */
static int
write_snapshot_sections(struct process* proc)
{
    int ret = -1;

    int fd = -1;
    void* elf = MAP_FAILED;
    size_t len = 0;
    struct stat st = { 0 };

    Elf_Ehdr* ehdr = NULL;
    Elf_Phdr* phdr = NULL;
    Elf_Shdr* shdr = NULL;
    const char shstr[] =
        "\0"
        ".shstrtab\0"
        ".anon\0"
        ".shlib\0"
        ".heap\0"
        ".stack\0"
        ".vdso\0"
        ".vsyscall\0"
        ".padding\0"
        ".vvar\0"
        ".fdinfo\0"
        ".regs\0"
        ".fpregs";

    struct snapshot* snap = proc->snap;

    if ((fd = open(opts.path, O_RDWR, S_IRWXU)) == -1) {
        report_error("can't open '%s': %s", opts.path, strerror(errno));
        goto cleanup;
    }

    if (fstat(fd, &st) < 0) {
        report_error("can't get stat of '%s': %s", opts.path, strerror(errno));
        goto cleanup;
    }

    len = st.st_size;
    elf = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf == MAP_FAILED) {
        report_error("can't mmap '%s': %s", opts.path, strerror(errno));
        goto cleanup;
    }

    ehdr = (Elf_Ehdr*) elf;
    phdr = (Elf_Phdr*) (elf + ehdr->e_phoff);

    if (lseek(fd, len, SEEK_SET) < 0) {
        report_error("can't seek in '%s': %s", opts.path, strerror(errno));
        goto cleanup;
    }

    ehdr->e_shnum = 0;

    /* Null section */

    shdr = add_section_header(shdr, ehdr, 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0);
    if (shdr == NULL)
        goto cleanup;

    /* .shstrtab */

    if (write(fd, shstr, sizeof(shstr)) != sizeof(shstr)) {
        report_error("can't write to '%s': %s", opts.path, strerror(errno));
        goto cleanup;
    }

    shdr = add_section_header(
        shdr, ehdr, get_section_name(".shstrtab", shstr, sizeof(shstr)),
        SHT_STRTAB, 0, len, sizeof(shstr), 0, 0, 0, 1, 0);
    if (shdr == NULL)
        goto cleanup;

    ehdr->e_shstrndx = 1;
    len += sizeof(shstr);

    /* .fdinfo */

    if (write(fd, snap->fdinfo, sizeof(struct fdinfo) * snap->nfdinfo) !=
        sizeof(struct fdinfo) * snap->nfdinfo) {
        report_error("can't write to '%s': %s", opts.path, strerror(errno));
        goto cleanup;
    }

    shdr = add_section_header(
        shdr, ehdr, get_section_name(".fdinfo", shstr, sizeof(shstr)),
        SHT_PSNAP_FDINFO, 0, len, sizeof(struct fdinfo) * snap->nfdinfo, 0, 0,
        0, sizeof(size_t), sizeof(struct fdinfo));
    if (shdr == NULL)
        goto cleanup;

    len += sizeof(struct fdinfo) * snap->nfdinfo;

    /* .regs */

    if (write(fd, snap->regs, sizeof(struct user_regs_struct)) !=
        sizeof(struct user_regs_struct)) {
        report_error("can't write to '%s': %s", opts.path, strerror(errno));
        goto cleanup;
    }

    shdr = add_section_header(
        shdr, ehdr, get_section_name(".regs", shstr, sizeof(shstr)),
        SHT_PSNAP_REGS, 0, len, sizeof(struct user_regs_struct), 0, 0, 0,
        sizeof(size_t), 0);
    if (shdr == NULL)
        goto cleanup;

    len += sizeof(struct user_regs_struct);

    /* .fpregs */

    if (write(fd, snap->fpregs, sizeof(struct user_fpregs_struct)) !=
        sizeof(struct user_fpregs_struct)) {
        report_error("can't write to '%s': %s", opts.path, strerror(errno));
        goto cleanup;
    }

    shdr = add_section_header(
        shdr, ehdr, get_section_name(".fpregs", shstr, sizeof(shstr)),
        SHT_PSNAP_FPREGS, 0, len, sizeof(struct user_fpregs_struct), 0, 0, 0,
        sizeof(size_t), 0);
    if (shdr == NULL)
        goto cleanup;

    len += sizeof(struct user_fpregs_struct);

    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        for (size_t j = 0; j < proc->nmaps; j++) {
            uint32_t name = 0;

            if (proc->maps[j].base != phdr[i].p_vaddr)
                continue;

            if (proc->maps[j].type == MT_ELF)
                break;

            switch (proc->maps[j].type)
            {
            case MT_ANON:
                name = get_section_name(".anon", shstr, sizeof(shstr));
                break;

            case MT_SHLIB:
                name = get_section_name(".shlib", shstr, sizeof(shstr));
                break;

            case MT_HEAP:
                name = get_section_name(".heap", shstr, sizeof(shstr));
                break;

            case MT_STACK:
                name = get_section_name(".stack", shstr, sizeof(shstr));
                break;

            case MT_VDSO:
                name = get_section_name(".vdso", shstr, sizeof(shstr));
                break;

            case MT_VSYSCALL:
                name = get_section_name(".vsyscall", shstr, sizeof(shstr));
                break;

            case MT_PADDING:
                name = get_section_name(".padding", shstr, sizeof(shstr));
                break;

            case MT_VVAR:
                name = get_section_name(".vvar", shstr, sizeof(shstr));
                break;
            
            default:
                break;
            }

            shdr = add_section_header(
                shdr, ehdr, name, SHT_PSNAP_MAP, phdr[i].p_vaddr,
                phdr[i].p_offset, phdr[i].p_filesz, SHF_ALLOC, 0, 0,
                phdr[i].p_align, 0);
            if (shdr == NULL)
                goto cleanup;
        }
    }

    if (write(fd, shdr, sizeof(Elf_Shdr) * ehdr->e_shnum) !=
        sizeof(Elf_Shdr) * ehdr->e_shnum) {
        report_error("can't write to '%s': %s", opts.path, strerror(errno));
        goto cleanup;
    }

    /* Update ELF header */

    ehdr->e_shoff = len;

    if (lseek(fd, 0, SEEK_SET) < 0) {
        report_error("can't seek in '%s': %s", opts.path, strerror(errno));
        goto cleanup;
    }

    if (write(fd, ehdr, sizeof(Elf_Ehdr)) != sizeof(Elf_Ehdr)) {
        report_error("can't write to '%s': %s", opts.path, strerror(errno));
        goto cleanup;
    }

    if (opts.debug) {
        for (size_t i = 0; i < ehdr->e_shnum; i++) {
            const char* name = &shstr[shdr[i].sh_name];

            report("Written %s section: addr=0x%08lx offset=0x%08lx size=0x%08lx",
                   *name == '\0' ? "NULL" : name, shdr[i].sh_addr,
                   shdr[i].sh_offset, shdr[i].sh_size);
        }
    }

    msync(elf, len, MS_SYNC);
    ret = 0;

 cleanup:
    munmap(elf, len);
    close(fd);

    if (ret == -1)
        unlink(opts.path);

    return ret;
}


static int
set_snapshot_permissions()
{
    return chmod(opts.path, S_IRUSR | S_IRGRP | S_IROTH);
}


/* Print usage message and exit */
static void
usage(const char* program_name, int status)
{
    if (status != EXIT_SUCCESS) {
        fprintf(stderr, "Try '%s --help' for more information.\n",
                program_name);
        exit(EXIT_FAILURE);
    } else {
        printf("Usage: %s [options] [-p pid] [-o output_file]\n"
               "\n"
               "Make process snapshot.\n"
               "\n"
               "Options:\n"
               "    -h, --help              display this help and exit\n"
               "    -d, --debug             print debug messages\n"
               "    -p, --pid               process PID\n"
               "    -o <file>               output file\n",
               program_name);
        exit(EXIT_SUCCESS);
    }
}


static void
parse_options(int argc, char* argv[])
{
    char c = 0;
    int long_optind = 0;
    struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"debug", no_argument, &opts.debug, 'd'},
        {"pid", required_argument, NULL, 'p'},
        {NULL, 0, NULL, 0}
    };

    while ((c = getopt_long(argc, argv, "hdp:o:", long_options,
                            &long_optind)) != -1) {
        switch(c) {
        case 0:
            if (long_options[long_optind].flag != 0)
                break;

            if ((opts.pid = atoi(optarg)) == 0) {
                report_error("invalid pid");
                exit(EXIT_FAILURE);
            }
            break;

        case 'h':
            usage(argv[0], EXIT_SUCCESS);

        case 'd':
            opts.debug = true;
            break;

        case 'p':
            if ((opts.pid = atoi(optarg)) == 0) {
                report_error("invalid pid");
                exit(EXIT_FAILURE);
            }
            break;

        case 'o':
            opts.path = optarg;
            break;

        default:
            usage(argv[0], EXIT_FAILURE);
        }
    }

    if (opts.pid == 0) {
        report_error("no pid");
        usage(argv[0], EXIT_FAILURE);
    } else if (opts.path == NULL) {
        report_error("no output file");
        usage(argv[0], EXIT_FAILURE);
    }
}


int
main(int argc, char* argv[])
{
    int ret = EXIT_FAILURE;

    struct process* proc = NULL;

    set_program_name(argv[0]);
    parse_options(argc, argv);

    if (!process_exists(opts.pid)) {
        report_error("process with the given pid does not exist");
        goto cleanup;
    }

    if (attach_to_process() < 0)
        goto cleanup;

    if ((proc = get_processrmation()) == NULL)
        goto cleanup;

    if (make_process_snapshot(proc->maps, proc->nmaps) < 0)
        goto cleanup;

    if (detach_from_process() < 0)
        goto cleanup;

    if (write_snapshot_sections(proc) < 0)
        goto cleanup;

    if (set_snapshot_permissions() < 0)
        goto cleanup;

    ret = EXIT_SUCCESS;

 cleanup:
    if (proc) {
        free(proc->maps);

        if (proc->snap) {
            free(proc->snap->fdinfo);
            free(proc->snap->regs);
            free(proc->snap->fpregs);
        }

        free(proc->snap);
    }

    free(proc);
    return ret;
}
