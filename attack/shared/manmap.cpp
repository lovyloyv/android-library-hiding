#include <android/log.h>

#include <vector>
#include <string>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <unistd.h>

#include <elf.h>
#include <dlfcn.h>

#define log(...) __android_log_print(ANDROID_LOG_DEBUG, "RemapAttack", __VA_ARGS__)

static inline void set_auxv(Elf64_auxv_t *auxv, uint64_t type, uint64_t value)
{
    auxv->a_type = type;
    auxv->a_un.a_val = value;
}

std::string get_libs_dir()
{
    // i really made this chopped, huh
    std::ifstream maps("/proc/self/maps");
    for (std::string line; std::getline(maps, line);)
    {
        if (line.find("libinjector.so") != std::string::npos)
        {
            auto pos = line.find_last_of('/');
            if (pos != std::string::npos)
            {
                auto last_part = line.substr(0, pos + 1); // 76562d6000-76563af000 r-xp 00000000 08:13 7995428                        /data/app/~~qz3xzytCGYOZaQtRjn7X6Q==/dev.remap.testapp-oitWjEZqbPGGsVR23NbZMQ==/lib/arm64/
                pos = last_part.find_first_of('/');
                if (pos != std::string::npos)
                {
                    return last_part.substr(pos);
                }
            }
        }
    }
    return "";
}

void *map_lib(const std::string &lib_name)
{
    std::string libs_dir = get_libs_dir();
    if (libs_dir.empty())
        return nullptr;

    log("libs_dir: %s", libs_dir.c_str());
    std::ifstream _file(libs_dir + lib_name, std::ios::binary);
    if (!_file)
        return nullptr;

    std::vector<uint8_t> elf_file((std::istreambuf_iterator<char>(_file)), std::istreambuf_iterator<char>());

    if (elf_file.size() < sizeof(Elf64_Ehdr))
        return nullptr;

    Elf64_Ehdr *ehdr = reinterpret_cast<Elf64_Ehdr *>(elf_file.data());

    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
        return nullptr;

    uint8_t *cursor = elf_file.data() + ehdr->e_phoff;
    const uint8_t *elf_end = elf_file.data() + elf_file.size();

    // on to the fun part.

    // we map the entire ELF file into memory as a single contiguous block
    auto page_size = sysconf(_SC_PAGESIZE);
    bool first_load{true};
    Elf64_Addr min_vaddr = UINT64_MAX, max_vaddr = 0, mapping_size = 0;
    for (int i = 0; i < ehdr->e_phnum; ++i)
    {
        Elf64_Phdr *phdr = reinterpret_cast<Elf64_Phdr *>(cursor);
        if (phdr->p_type == PT_LOAD)
        {
            auto segment_min = phdr->p_vaddr & ~(page_size - 1);
            auto segment_max = (phdr->p_vaddr + phdr->p_memsz + page_size - 1) & ~(page_size - 1);
            log("segment_min: %p, segment_max: %p", reinterpret_cast<void *>(segment_min), reinterpret_cast<void *>(segment_max));
            if (first_load)
            {
                min_vaddr = segment_min;
                first_load = false;
            }
            else if (segment_min < min_vaddr)
                min_vaddr = segment_min;

            if (segment_max > max_vaddr)
                max_vaddr = segment_max;
        }
        cursor += sizeof(Elf64_Phdr);
    }
    mapping_size = max_vaddr - min_vaddr;

    log("min_vaddr: %p, max_vaddr: %p", (min_vaddr), (max_vaddr));
    log("mapping size: %zu", mapping_size);
    auto mapped_lib = mmap(nullptr, mapping_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapped_lib == MAP_FAILED)
        return nullptr;

    auto base = static_cast<uint8_t *>(mapped_lib);
    uintptr_t load_bias = reinterpret_cast<uintptr_t>(base) - min_vaddr;

    log("mapped elf at address %p", base);

    // now we map the segments inside of it
    cursor = elf_file.data() + ehdr->e_phoff;
    for (int i = 0; i < ehdr->e_phnum; ++i)
    {
        Elf64_Phdr *phdr = reinterpret_cast<Elf64_Phdr *>(cursor);
        if (phdr->p_type == PT_LOAD)
        {
            void *seg_addr = reinterpret_cast<void *>(base + (phdr->p_vaddr - min_vaddr));
            std::memcpy(seg_addr, elf_file.data() + phdr->p_offset, phdr->p_filesz);
            if (phdr->p_memsz > phdr->p_filesz)
                std::memset(reinterpret_cast<uint8_t *>(seg_addr) + phdr->p_filesz, 0, phdr->p_memsz - phdr->p_filesz);

            log("mapped segment at address %p", seg_addr);
        }

        cursor += sizeof(Elf64_Phdr);
    }

    // now we can do dynamic
    // relocations
    Elf64_Shdr *dynsym_shdr = nullptr;
    Elf64_Shdr *dynstr_shdr = nullptr;
    cursor = elf_file.data() + ehdr->e_shoff;
    for (int i = 0; i < ehdr->e_shnum; ++i)
    {
        Elf64_Shdr *shdr = reinterpret_cast<Elf64_Shdr *>(cursor);
        if (shdr->sh_type == SHT_DYNSYM)
            dynsym_shdr = shdr;
        cursor += sizeof(Elf64_Shdr);
    }

    if (!dynsym_shdr ||
        ehdr->e_shentsize != sizeof(Elf64_Shdr) ||
        dynsym_shdr->sh_link >= ehdr->e_shnum)
    {
        return nullptr;
    }

    dynstr_shdr = reinterpret_cast<Elf64_Shdr *>(elf_file.data() + ehdr->e_shoff + size_t(dynsym_shdr->sh_link) * ehdr->e_shentsize);
    if (dynstr_shdr->sh_type != SHT_STRTAB)
        return nullptr;

    auto resolve_runtime_symbol = [&](size_t symbol_index) -> void *
    {
        if (!dynsym_shdr || !dynstr_shdr)
            return 0;

        Elf64_Sym *symtab = reinterpret_cast<Elf64_Sym *>(elf_file.data() + dynsym_shdr->sh_offset);
        const char *strtab = reinterpret_cast<const char *>(elf_file.data() + dynstr_shdr->sh_offset);

        Elf64_Sym &sym = symtab[symbol_index];
        auto type = ELF64_ST_TYPE(sym.st_info);

        // log("resolving symbol at index: %zu", symbol_index);
        if (sym.st_shndx == SHN_ABS)
            return reinterpret_cast<void *>(sym.st_value);

        if (sym.st_shndx != SHN_UNDEF &&
            sym.st_shndx < SHN_LORESERVE &&
            (type == STT_FUNC ||
             type == STT_OBJECT ||
             type == STT_NOTYPE))
        {
            return reinterpret_cast<void *>(load_bias + sym.st_value);
        }

        const char *sym_name = strtab + sym.st_name;

        // log("resolving symbol: %s", sym_name);

        auto addr = dlsym(RTLD_DEFAULT, sym_name);
        if (!addr)
        {
            if (auto err = dlerror(); err)
            {
                log("failed to resolve symbol: %s, error: %s", sym_name, err);
                return nullptr;
            }
        }
        return addr;
    };

    auto resolve_rela = [load_bias, resolve_runtime_symbol](Elf64_Rela *rela) -> bool
    {
        auto code = ELF64_R_TYPE(rela->r_info);

        // Delta + A
        if (code == R_AARCH64_RELATIVE)
        {
            if (rela->r_addend != 0)
            {
                auto *delta = reinterpret_cast<Elf64_Addr *>(
                    load_bias + rela->r_offset);
                *delta = load_bias + rela->r_addend;
            }
            return true;
        }

        // Indirect(Delta + A)
        else if (code == R_AARCH64_IRELATIVE)
        {
            auto *indirect = reinterpret_cast<Elf64_Addr *>(load_bias + rela->r_offset);
            auto resolver_addr = reinterpret_cast<Elf64_Addr (*)(void)>(load_bias + rela->r_addend);

            #define _IFUNC_ARG_HWCAP (1ULL << 62)
            typedef struct __ifunc_arg_t
            {
                /** Set to sizeof(__ifunc_arg_t). */
                unsigned long _size;
                /** Set to getauxval(AT_HWCAP). */
                unsigned long _hwcap;
                /** Set to getauxval(AT_HWCAP2). */
                unsigned long _hwcap2;
            } __ifunc_arg_t;

            typedef Elf64_Addr (*ifunc_resolver_t)(uint64_t, __ifunc_arg_t *);
            static __ifunc_arg_t arg;
            static bool initialized = false;
            if (!initialized)
            {
                initialized = true;
                arg._size = sizeof(__ifunc_arg_t);
                arg._hwcap = getauxval(AT_HWCAP);
                arg._hwcap2 = getauxval(AT_HWCAP2);
            }

            log("resolving IFUNC at address: %p", reinterpret_cast<void *>(resolver_addr));
            *indirect = reinterpret_cast<ifunc_resolver_t>(resolver_addr)(arg._hwcap | _IFUNC_ARG_HWCAP, &arg);
            return true;
        }

        // S + A
        else if (code == R_AARCH64_GLOB_DAT || code == R_AARCH64_JUMP_SLOT || code == R_AARCH64_ABS64)
        {
            auto *where = reinterpret_cast<Elf64_Addr *>(load_bias + rela->r_offset);
            auto symbol_index = ELF64_R_SYM(rela->r_info);
            void *symbol_address = resolve_runtime_symbol(symbol_index);
            if (!symbol_address)
                return false;

            *where = reinterpret_cast<Elf64_Addr>(symbol_address) + rela->r_addend;
            return true;
        }

        else
        {
            log("unsupported relocation type: %u", code);
            return false;
        }

    };

    cursor = elf_file.data() + ehdr->e_phoff;
    Elf64_Rela *rela = nullptr;
    Elf64_Xword rela_size = 0;

    Elf64_Addr jmprel_vaddr = 0;
    Elf64_Xword pltrel_size = 0;
    Elf64_Xword plt_rel_type = 0;
    for (int i = 0; i < ehdr->e_phnum; ++i)
    {
        Elf64_Phdr *phdr = reinterpret_cast<Elf64_Phdr *>(cursor);

        if (phdr->p_type != PT_DYNAMIC)
        {
            cursor += sizeof(Elf64_Phdr);
            continue;
        }

        Elf64_Dyn *dyn = reinterpret_cast<Elf64_Dyn *>(elf_file.data() + phdr->p_offset);
        for (Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; ++d)
        {
            if (d->d_tag == DT_RELA)
            {
                Elf64_Addr rela_vaddr = d->d_un.d_ptr;
                rela = reinterpret_cast<Elf64_Rela *>(base + (rela_vaddr - min_vaddr));
            }

            if (d->d_tag == DT_RELASZ)
            {
                rela_size = d->d_un.d_val;
            }

            if (d->d_tag == DT_RELAENT)
            {
                Elf64_Xword rela_ent = d->d_un.d_val;
                log("RELA entry size: %lu", rela_ent);
            }

            if (d->d_tag == DT_JMPREL)
            {
                jmprel_vaddr = d->d_un.d_ptr;
            }

            if (d->d_tag == DT_PLTRELSZ)
            {
                // size of the PLT relocations
                pltrel_size = d->d_un.d_val;
            }

            if (d->d_tag == DT_PLTREL)
            {
                plt_rel_type = d->d_un.d_val;
                log("PLT relocation type: %lu", plt_rel_type);
            }
        }

        cursor += sizeof(Elf64_Phdr);
    }

    // apply relocations
    {
        if (rela && rela_size > 0)
        {
            std::vector<Elf64_Rela> rela_copy;
            size_t count = rela_size / sizeof(Elf64_Rela);
            rela_copy.assign(rela, rela + count);

            for (size_t i = 0; i < rela_copy.size(); ++i)
            {
                Elf64_Rela *current = &rela_copy[i];

                // log(
                //     "i=%zu/%zu entry=%p offset=%#llx type=%u sym=%u addend=%#llx",
                //     i,
                //     rela_copy.size(),
                //     static_cast<void *>(current),
                //     static_cast<unsigned long long>(current->r_offset),
                //     static_cast<unsigned>(ELF64_R_TYPE(current->r_info)),
                //     static_cast<unsigned>(ELF64_R_SYM(current->r_info)),
                //     static_cast<unsigned long long>(current->r_addend));

                resolve_rela(current);
            }
        }
        log("rela relocations done");
    }

    if (jmprel_vaddr != 0 && pltrel_size > 0 && plt_rel_type == DT_RELA)
    {
        Elf64_Rela *jmprel = reinterpret_cast<Elf64_Rela *>(base + (jmprel_vaddr - min_vaddr));
        size_t count = pltrel_size / sizeof(Elf64_Rela);
        for (size_t i = 0; i < count; ++i)
        {
            resolve_rela(&jmprel[i]);
        }
    }
    log("plt relocations done");

    // a serious attacker will destroy their elf header ( and handle the consequences of it accwordingly ) >:D
    memset(base, 0, sizeof(Elf64_Ehdr));

    // protection
    cursor = elf_file.data() + ehdr->e_phoff;
    for (int i = 0; i < ehdr->e_phnum; ++i)
    {
        Elf64_Phdr *phdr = reinterpret_cast<Elf64_Phdr *>(cursor);
        if (phdr->p_type == PT_LOAD)
        {
            int prot = PROT_NONE;
            if (phdr->p_flags & PF_R)
                prot |= PROT_READ;
            if (phdr->p_flags & PF_W)
                prot |= PROT_WRITE;
            if (phdr->p_flags & PF_X)
                prot |= PROT_EXEC;

            size_t align_up = (phdr->p_memsz + page_size -1) & ~(page_size - 1);
            mprotect(base + (phdr->p_vaddr - min_vaddr), align_up, prot);
        }

        cursor += sizeof(Elf64_Phdr);
    }

    // constructors
    cursor = elf_file.data() + ehdr->e_phoff;
    for (int i = 0; i < ehdr->e_phnum; ++i)
    {
        Elf64_Phdr *phdr = reinterpret_cast<Elf64_Phdr *>(cursor);
        log("phdr->p_type: %u", phdr->p_type);

        if (phdr->p_type == PT_DYNAMIC)
        {
            log("found PT_DYNAMIC segment at offset %zu", phdr->p_offset);

            Elf64_Dyn *dyn = reinterpret_cast<Elf64_Dyn *>(elf_file.data() + phdr->p_offset);
            Elf64_Addr init_array_vaddr = 0;
            Elf64_Xword init_array_size = 0;

            // harvest the VMA pointers and sizes first
            for (Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; ++d)
            {
                if (d->d_tag == DT_INIT_ARRAY)
                {
                    init_array_vaddr = d->d_un.d_ptr;
                }
                else if (d->d_tag == DT_INIT_ARRAYSZ)
                {
                    init_array_size = d->d_un.d_val;
                }
            }

            log("init_array_vaddr: %p, init_array_size: %zu", (void *)init_array_vaddr, init_array_size);

            // translate the vmas to our mapped memory space
            if (init_array_vaddr != 0 && init_array_size != 0)
            {
                size_t count = init_array_size / sizeof(Elf64_Addr);
                auto init_array = reinterpret_cast<Elf64_Addr *>(
                    base + (init_array_vaddr - min_vaddr));
                for (size_t j = 0; j < count; ++j)
                {
                    Elf64_Addr func_vaddr = init_array[j];
                    log("func_vaddr: %p", (void *)func_vaddr);

                    if (func_vaddr)
                    {
                        void (*init_func)() = reinterpret_cast<void (*)()>(func_vaddr);
                        log("calling init function at address %p", (void *)init_func);
                        init_func();
                    }
                }
                break;
            }
        }
        cursor += sizeof(Elf64_Phdr);
    }
    return mapped_lib;
}