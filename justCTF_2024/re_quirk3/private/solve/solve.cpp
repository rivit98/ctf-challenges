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

#include "constants.h"


int main() {
    srand(0x1337);

    int idx = 0;
    for (auto e : expected)
    {
        uint32_t r = rand();
        e = std::rotl(static_cast<uint32_t>(e), idx);
        e ^= r;
        

        int c = std::rotr((uint32_t)e, 5);
        c = c & 0xFF;
        std::cout << (char)c;

        idx += 1;
    }

    std::cout << std::endl;
}
