#include <android/log.h>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <link.h>
#include <unistd.h>
#include <inttypes.h>
#include <cstdio>

/**
 * list of libs that should be blacklisted, this is what we can directly target.
 */
std::vector< std::string > BLACKLIST = {
    "libinjector.so",
    "libremap.so",
    "libmanmap.so"
};

/**
 * list of libs that our app should only have in its lib dir, anything else is bad.
 */
std::vector< std::string > LEGIT_APP_LIBS = {
    "libdefend.so"
};

std::string scan_maps()
{
    std::vector< std::string > app_libs;
    std::vector< std::string > found; // no repetitions, real-world youd use a bitfield here to know your hackflags.
    auto contains = [&found](const std::string &lib) {
        return std::find(found.begin(), found.end(), lib) != found.end();
    };

    // detection results.
    std::stringstream ss;
    ss << "pid: " << getpid() << "\n";

    std::ifstream maps("/proc/self/maps");
    for (std::string line; std::getline(maps, line);)
    {
        for (const auto &lib : BLACKLIST)
        {
            if (line.find(lib) != std::string::npos && !contains(lib))
            {
                __android_log_print(ANDROID_LOG_INFO, "Defend", "found blacklisted lib: %s", lib.c_str());
                ss << "blacklisted-" << lib << "\n";

                found.push_back(lib);
            }
        }

        if ( line.find("dev.remap.testapp") != std::string::npos && line.rfind("lib") != std::string::npos && !contains(line.substr(line.rfind("lib"))))
        {
            std::string lib_name = line.substr(line.rfind("lib"));
            
            app_libs.push_back(lib_name);
            found.push_back(lib_name);
            
            __android_log_print(ANDROID_LOG_INFO, "Defend", "found app lib: %s", lib_name.c_str());
            ss << "app-" << lib_name << "\n";
        }
    }

    for (const auto &lib : app_libs)
    {
        // lib that is not in the legitimate app libs list
        if (std::find(LEGIT_APP_LIBS.begin(), LEGIT_APP_LIBS.end(), lib) == LEGIT_APP_LIBS.end())
        {
            __android_log_print(ANDROID_LOG_INFO, "Defend", "found non-legit app lib: %s", lib.c_str());
            ss << "illegitimate-" << lib << "\n";
        }
    }

    return ss.str();
}

std::string scan_objs()
{
    /**
     * will catch remapped binaries, as they are still linked and therefore the linker has a record of them.
     */

    std::vector< std::string > app_libs;
    std::stringstream ss;

    struct _u
    {
        std::vector<std::string> *app_libs;
        std::stringstream *ss;
    } u{&app_libs, &ss};

    dl_iterate_phdr([](struct dl_phdr_info *info, size_t size, void *data) -> int {
        (void)size;
        if (info && info->dlpi_name)
        {
            _u *u = static_cast<_u *>(data);
            std::stringstream *ss = u->ss;
            std::vector<std::string> *app_libs = u->app_libs;

            std::string path = info->dlpi_name;
            auto pos = path.rfind("lib");
            if ( pos == std::string::npos )
            {
                // ideally, you should NOT do this.
                // by this, i mean you should not rely on the presence of "lib" in the path.
                // instead, you should still check if this is in your app-space or if youre doing memscans
                // scan it anyway. this is because attackers can and will circumvent your defense by literal renames.
                return 0;
            }

            std::string lib_name = path.substr(pos);

            __android_log_print(ANDROID_LOG_INFO, "Defend", "found object: %s", lib_name.c_str());

            if (std::find(BLACKLIST.begin(), BLACKLIST.end(), lib_name) != BLACKLIST.end())
            {
                __android_log_print(ANDROID_LOG_INFO, "Defend", "found blacklisted lib in link_map: %s", lib_name.c_str());
                
                *ss << "blacklisted-" << lib_name << "\n";
            }

            if (path.find("dev.remap.testapp") != std::string::npos && path.rfind("lib") != std::string::npos)
            {
                app_libs->push_back(lib_name);
                *ss << "app-" << lib_name << "\n";
            }
        }
        return 0;
    }, &u);

    for (const auto &lib : app_libs)
    {
        // lib that is not in the legitimate app libs list
        if (std::find(LEGIT_APP_LIBS.begin(), LEGIT_APP_LIBS.end(), lib) == LEGIT_APP_LIBS.end())
        {
            __android_log_print(ANDROID_LOG_INFO, "Defend", "found non-legit app lib: %s", lib.c_str());
            ss << "illegitimate-" << lib << "\n";
        }
    }

    return ss.str();
}

std::string scan_anonymous()
{
    /**
     * manual mapped libraries are strongest, but the kernel has a record of ALL located memory, including anon and deleted.
     * however scanning for sussy anon elfies is.. quite costly to us.
     * 
     * additionally, we cant rely on elf magic to identify library ranges.
    */

    // bad manual mappers like the one here can leave hints like an rwx large alloc.
    // BUT! a good mapper that maps-per-segment will cause allocations to be randomly distributed and properly protected
    // making it impossible to reliably detect this mapping, therefore any detections on injection would depend on the payload having a flaw like an exposed string
    // which gets caught on deep-mem-scans
    /*
        6fdb620000-6fdb6f6000 r-xp 00000000 00:00 0 
        6fdb6f6000-6fdb708000 rwxp 00000000 00:00 0  <- manual mapped.
        6fdb708000-6fdb7e4000 r-xp 00000000 00:00 0 
        6fdb7e4000-6fdb7e7000 ---p 00000000 00:00 0 
        6fdb7e7000-6fdb7f1000 r--p 00000000 00:00 0 
        6fdb7f1000-6fdb7f4000 ---p 00000000 00:00 0 
        6fdb7f4000-6fdb7f5000 rw-p 00000000 00:00 0 

        6fd9f12000-6fd9fec000 r-xp 00000000 08:13 7995429 trunc/libdefend.so
        6fd9fec000-6fd9fef000 ---p 00000000 00:00 0 
        6fd9fef000-6fd9ff9000 r--p 000d9000 08:13 7995429 trunc/libdefend.so
        6fd9ff9000-6fd9ffc000 ---p 00000000 00:00 0 
        6fd9ffc000-6fd9ffd000 rw-p 000e2000 08:13 7995429 trunc/libdefend.so
    */

    std::stringstream ss;
    std::ifstream maps("/proc/self/maps");
    
    for (std::string line; std::getline(maps, line);)
    {
        uintptr_t start = 0, end = 0;
        uint64_t offset = 0, inode = 0;
        char perms[5] = {};
        char dev[25] = {};
        int path_pos = -1;

        const int fields = std::sscanf(
            line.c_str(),
            "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNx64
            " %24s %" SCNu64 " %n",
            &start, &end, perms, &offset, dev, &inode, &path_pos);

        if (fields != 6 || path_pos < 0 || start >= end)
        {
            __android_log_print(ANDROID_LOG_INFO, "Defend", "parse fail: %s", line.data());
            continue;
        }

        // a real implementation must verify that the allocation looked at is truly abnormal before acting
        if (strcmp(perms, "rwxp") == 0)
        {
            // *should* NEVEr happen naturally.
            ss << "rwxp-" << std::hex << start << "\n";
        }
    }

    return ss.str();
}
