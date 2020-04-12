#include <string.h>

#include <iostream>
#include <string>
#include <chrono>

#include "MurmurHash3.h"

void printHash(const uint8_t* hash, int size) {
    for(int i=0; i<size; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

class Timer {
public:
    Timer() {
        start_ = std::chrono::high_resolution_clock::now();
    }
    ~Timer() {
        auto end = std::chrono::high_resolution_clock::now();
        auto endD = std::chrono::time_point_cast<std::chrono::microseconds>(end).time_since_epoch();
        auto startD = std::chrono::time_point_cast<std::chrono::microseconds>(start_).time_since_epoch();
        auto duration = (endD-startD).count();
        total += duration;
    }
    static uint64_t total;
private:
    std::chrono::time_point<std::chrono::high_resolution_clock> start_;
};

uint64_t Timer::total = 0;

int main(int argc, char* argv[]) {
    const int nargs = argc-1;
    if (nargs != 3) {
        std::cerr << "error: need 2 args: hash, chunkSize and path\n";
        return 1;
    }
    char** args = argv+1;
    std::string hashName(args[0]);
    char* path = args[2];

    // in bytes
    const long int kBufSize = atoi(args[1])*(1<<20);
    const int kMurmurSize = 16;

    if (hashName == "sha1") {

    } else if (hashName == "murmur") {
        FILE* f = fopen(path, "rb");
        if (f == nullptr) {
            std::cerr << "error: fopen: " << strerror(errno) << "\n";
            return 1;
        }
        uint8_t* buf = new uint8_t[kBufSize];
        bool isErr = false;
        while(!feof(f)) {
            int n = fread(buf, 1, kBufSize, f);
            if (ferror(f)) {
                std::cerr << "error: fread\n";
                isErr = true;
                break;
            }
            {
                Timer t;
                uint8_t out[kMurmurSize];
                MurmurHash3_x64_128(buf, n, 42, out);
            }
        }
        auto totalMs = (Timer::total * 0.001);
        std::cout << totalMs << "ms\n";
        fclose(f);
        if(isErr) {
            return 1;
        }
    } else {
        std::cerr << "error: hash '" << hashName << "' is not supported\n";
        return 1;
    }
    return 0;
}
