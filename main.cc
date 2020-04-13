#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>

#include <iostream>
#include <string>
#include <chrono>
#include <array>
#include <vector>

#include <openssl/sha.h>

#include "MurmurHash3.h"
#include "xxh3.h"


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
        std::cerr << "error: need 2 args: hash, path and chunkSize\n";
        return 1;
    }

    char** args = argv+1;
    std::string hashName(args[0]);
    char* path = args[1];

    if (hashName == "sha1") {
        FILE* f = fopen(path, "rb");
        if (f == nullptr) {
            std::cerr << "error: fopen: " << strerror(errno) << "\n";
            return 1;
        }

        // in bytes
        const long int kBufSize = atoi(args[2])*(1<<20);
        uint8_t* buf = new uint8_t[kBufSize];

        SHA_CTX ctx;
        SHA1_Init(&ctx);

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
                SHA1_Update(&ctx, buf, n);
            }
        }

        fclose(f);

        if(isErr) {
            return 1;
        }

        const int kSha1Size = 20;
        uint8_t hash[kSha1Size];
        {
            Timer t;
            SHA1_Final(hash, &ctx);
        }
        printHash(hash, kSha1Size);

        auto totalMs = (Timer::total * 0.001);
        std::cout << totalMs << "ms\n";
    } else if (hashName == "murmur") {
        FILE* f = fopen(path, "rb");
        if (f == nullptr) {
            std::cerr << "error: fopen: " << strerror(errno) << "\n";
            return 1;
        }

        struct stat st;
        if(stat(path, &st) < 0) {
            std::cerr << "error: fstat: " << strerror(errno) << "\n";
            return 1;
        }

        // in bytes
        const long int kBufSize = atoi(args[2])*(1<<20);
        uint8_t* buf = new uint8_t[kBufSize];

        const int kMurmurSize = 16;

        const int kNrChunks = std::ceil(static_cast<double>(st.st_size) / static_cast<double>(kBufSize));

        std::vector<std::array<uint8_t, kMurmurSize>> chunkHashes;
        chunkHashes.reserve(kNrChunks);

        int i = 0;

        bool isErr = false;
        while(!feof(f)) {
            int n = fread(buf, 1, kBufSize, f);
            if (ferror(f)) {
                std::cerr << "error: fread\n";
                isErr = true;
                break;
            }
            std::array<uint8_t, kMurmurSize> hash;
            {

                Timer t;
                MurmurHash3_x64_128(buf, n, 42, hash.data());
            }
            chunkHashes.insert(chunkHashes.begin()+i, hash);
            i++;
        }

        fclose(f);

        if(isErr) {
            return 1;
        }

        const int kFinalHashBufSize = kNrChunks*kMurmurSize;
        uint8_t finalHashBuf[kFinalHashBufSize];
        for(int i=0; i<chunkHashes.size(); ++i) {
            memcpy(finalHashBuf+(i*kMurmurSize), chunkHashes[i].data(), chunkHashes[i].size());
        }

        uint8_t finalHash[kMurmurSize];
        {
            Timer t;
            MurmurHash3_x64_128(finalHashBuf, kFinalHashBufSize, 42, finalHash);
        }
        printHash(finalHash, kMurmurSize);

        auto totalMs = (Timer::total * 0.001);
        std::cout << totalMs << "ms\n";
    } else if (hashName == "xx") {
        FILE* f = fopen(path, "rb");
        if (f == nullptr) {
            std::cerr << "error: fopen: " << strerror(errno) << "\n";
            return 1;
        }

        // in bytes
        const long int kBufSize = atoi(args[2])*(1<<20);
        uint8_t* buf = new uint8_t[kBufSize];

        XXH3_state_t state;
        XXH3_128bits_reset(&state);

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
                XXH3_128bits_update(&state, buf, n);
            }
        }

        fclose(f);

        if(isErr) {
            return 1;
        }

        XXH128_hash_t finalHash;
        {
            Timer t;
            finalHash = XXH3_128bits_digest(&state);
        }
        XXH128_canonical_t finalHashCanonical;
        XXH128_canonicalFromHash(&finalHashCanonical, finalHash);
        printHash(finalHashCanonical.digest, sizeof(finalHashCanonical));

        auto totalMs = (Timer::total * 0.001);
        std::cout << totalMs << "ms\n";
    } else {
        std::cerr << "error: hash '" << hashName << "' is not supported\n";
        return 1;
    }

    return 0;
}
