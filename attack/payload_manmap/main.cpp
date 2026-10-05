#include <android/log.h>
#include <string>
#include <thread>
#include <dlfcn.h>
#include <link.h>

void remap_lib(const std::string& lib_name);

#define log(...) __android_log_print(ANDROID_LOG_DEBUG, "RemapAttack", __VA_ARGS__)

extern "C" __attribute__((visibility("default")))
const char* payload_message() {
    return "Hello from libmanmap.so";
}

__attribute__((constructor)) static void on_load() {
    __android_log_print(ANDROID_LOG_INFO, "RemapAttack", "%s", payload_message());

    // payload hides its own injector.
    remap_lib("libinjector.so");
}
