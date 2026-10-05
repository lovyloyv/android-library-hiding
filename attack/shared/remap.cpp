#include <android/log.h>
#include <vector>
#include <string>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <sys/mman.h>
#include <unistd.h>

#define log(...) __android_log_print(ANDROID_LOG_DEBUG, "RemapAttack", __VA_ARGS__)

void remap_lib(const std::string& lib_name)
{
    /*
        we look up each memory segment of our lib and record it,
        then we remap each one of them to a different memory location.

        this effectively *hides* our library from a maps-lookup attack at practically zero-cost for us.
    */

    struct module_info
    {
        uintptr_t start;
        uintptr_t end;
        uint8_t perms;
    };

    const auto get_modules = [&]() -> std::vector<module_info>
    {
        std::vector<module_info> modules;

        std::ifstream maps("/proc/self/maps");
        for (std::string line; std::getline(maps, line);)
        {
            if (line.find(lib_name) == std::string::npos)
                continue;

            uintptr_t start, end, offset;
            char perms[10], path[255], dev[25];
            ino_t inode;
            sscanf(line.data(), "%lx-%lx %s %ld %s %ld %s", &start, &end, perms, &offset, dev, &inode, path);

            module_info mi{ };
            mi.start = start;
            mi.end = end;

            if (strchr(perms, 'r'))
                mi.perms |= PROT_READ;
            if (strchr(perms, 'w'))
                mi.perms |= PROT_WRITE;
            if (strchr(perms, 'x'))
                mi.perms |= PROT_EXEC;

            modules.push_back(mi);
        }
        return modules;
    };

    auto modules = get_modules();
    for (const auto &module : modules)
    {
        size_t size = module.end - module.start;
        void *alloc = mmap(0, size, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        std::string str_perms{ };
        if (module.perms & PROT_READ)
            str_perms.append("r");
        if (module.perms & PROT_WRITE)
            str_perms.append("w");
        if (module.perms & PROT_EXEC)
            str_perms.append("x");

        log("remap %zu -> %p (%s)", module.start, alloc, str_perms.data());

        if ((module.perms & PROT_READ) == 0)
            mprotect(alloc, size, PROT_READ);

        memmove(alloc, reinterpret_cast<void *>(module.start), size);
        mremap(alloc, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, module.start);

        mprotect(reinterpret_cast<void *>(module.start), size, module.perms);
    }
}