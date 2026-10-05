#include <android/log.h>
#include <dlfcn.h>
#include <string>
#include <thread>

void remap_lib(const std::string& lib_name);
void* map_lib(const std::string& lib_name);

extern "C" __attribute__((visibility("default")))
const char* injector_message() {
    return "Hello from libinjector.so";
}

__attribute__((constructor)) static void on_load() {
    __android_log_print(ANDROID_LOG_INFO, "RemapAttack", "%s", injector_message());

    // 1: manual map
    {
        map_lib("libmanmap.so");
    }

    // 2: dlopen + remap
    {
        dlopen("libremap.so", RTLD_LAZY);

        // injector hides its payload.
        remap_lib("libremap.so");
    }

}
