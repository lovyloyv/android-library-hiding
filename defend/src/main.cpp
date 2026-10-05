#include <jni.h>
#include <string>

std::string scan_maps();
std::string scan_objs();
std::string scan_anonymous();

// Keep these exported and out of line so experiments can locate each function.
extern "C" __attribute__((visibility("default"), noinline))
const char* defend_first_label() {
    return "Label 1: Hello from libdefend.so";
}

extern "C" __attribute__((visibility("default"), noinline))
const char* defend_second_label() {
    return "Label 2: Native code is running";
}

extern "C" JNIEXPORT jstring JNICALL
Java_dev_remap_testapp_MainActivity_firstLabel(JNIEnv* env, jclass) {
    std::string maps_result = scan_maps();
    return env->NewStringUTF(maps_result.data());
}

extern "C" JNIEXPORT jstring JNICALL
Java_dev_remap_testapp_MainActivity_secondLabel(JNIEnv* env, jclass) {
    std::string mem_result = scan_objs();
    std::string anon_result = scan_anonymous();

    std::string final = mem_result + "\n" + anon_result;
    return env->NewStringUTF(final.data());
}
