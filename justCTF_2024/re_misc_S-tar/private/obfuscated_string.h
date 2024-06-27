#pragma once

#include <cstdint>

constexpr auto TIME = __TIME__;
constexpr auto seed = static_cast<int>(TIME[7]) +
                      static_cast<int>(TIME[6]) * 10 +
                      static_cast<int>(TIME[4]) * 60 +
                      static_cast<int>(TIME[3]) * 600 +
                      static_cast<int>(TIME[1]) * 3600 +
                      static_cast<int>(TIME[0]) * 36000;


constexpr uint32_t prng(const uint32_t input) {
    return input * 48271 % 0x7fffffff;
}

template<typename T, size_t N>
struct encrypted {
    T data[N];
};

template<size_t N>
constexpr auto crypt(const char (&input)[N]) {
    encrypted<char, N> blob{};
    for (uint32_t index{0}, stream{seed}; index < N; index++) {
        stream = prng(stream);
        blob.data[index] = input[index] ^ stream;
    }
    return blob;
}

#define XOR_STRING(STRING)  ([] __attribute__ ((optimize(0))){  \
    constexpr auto _{ crypt(STRING) };                          \
    return std::string{ crypt(_.data).data };                   \
}())
