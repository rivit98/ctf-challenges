#include <cstdint>
#include <array>
#include <iostream>

int randSeed = 0;

void srand(unsigned seed){
    randSeed = seed;
}

int rand(void){
    randSeed = (69069 * randSeed + 1);
    return randSeed & 0x7fff;
}

#ifdef CTFGUIDE
#include "ctfguide.h"
#elif CTFLEARN
#include "ctflearn.h"
#else
#error "specify platform"
#endif


int main() {
    srand(0xdeadbeef);

    for (auto e : expected)
    {
        uint32_t r = rand();
        r = std::rotl(r, 5);
        e = e ^ r;

        int c = std::rotl((uint32_t)e, 5);
        c = c & 0xFF;
        std::cout << (char)c;
    }

    std::cout << std::endl;
}
