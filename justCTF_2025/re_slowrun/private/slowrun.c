#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <BigInt/BigInt.h>

const char* mod_str = "12871709638832864416674237492708808074465131233250468097567609804146306910998417223517320307084142930385333755674444057095681119233485961920941215894136808839080569675919567597231";
const char* correction_str = "805129649450289111374098215345043938348341847793365469885914570440914675704049341968773123354333661444680237475120349087680072042981825910641377252873686258216120616639500404381";

BigInt* g(BigInt* x);
BigInt* f(BigInt* x);

BigInt* f(BigInt* x) {
    BigInt* res = NULL;
    BigInt* s1 = NULL;
    BigInt* s2 = NULL;
    BigInt* s4 = NULL;
    BigInt* s2_arg = NULL;

    if(BigInt_compare_int(x, 0) == 0) {
        return BigInt_construct(2);
    }
    if(BigInt_compare_int(x, 1) <= 0) {
        return BigInt_construct(1);
    }

    res = BigInt_construct(0);

    // 73 * x ** 5
    s1 = BigInt_construct(73);
    BigInt_multiply(s1, x);
    BigInt_multiply(s1, x);
    BigInt_multiply(s1, x);
    BigInt_multiply(s1, x);
    BigInt_multiply(s1, x);


    // 8 * x ** 3
    s4 = BigInt_construct(8);
    BigInt_multiply(s4, x);
    BigInt_multiply(s4, x);
    BigInt_multiply(s4, x);


    // g(x-1)
    s2_arg = BigInt_clone(x, BigInt_strlen(x) + 1);
    BigInt_subtract_int(s2_arg, 1);
    s2 = g(s2_arg);


    // x - 4
    BigInt_add(res, x);
    BigInt_subtract_int(res, 4);

    BigInt_add(res, s1);
    BigInt_add(res, s2);
    BigInt_add(res, s4);


    BigInt_free(s1);
    BigInt_free(s2);
    BigInt_free(s4);
    BigInt_free(s2_arg);
    return res;
}

BigInt* g(BigInt* x) {
    BigInt* res = NULL;
    BigInt* s1 = NULL;
    BigInt* s2 = NULL;
    BigInt* s3 = NULL;
    BigInt* s4 = NULL;
    BigInt* s1_arg = NULL;
    BigInt* s2_arg = NULL;
    BigInt* s3_arg = NULL;

    if(BigInt_compare_int(x, 1) <= 0) {
        return BigInt_construct(1);
    }
    res = BigInt_construct(0);

    // f(x-1)
    s1_arg = BigInt_clone(x, BigInt_strlen(x) + 1);
    BigInt_subtract_int(s1_arg, 1);
    s1 = f(s1_arg);


    // 3 * f(x-2)
    s2_arg = BigInt_clone(x, BigInt_strlen(x) + 1);
    BigInt_subtract_int(s2_arg, 2);
    s2 = f(s2_arg);
    BigInt_multiply_int(s2, 3);


    // 5 * f(x-3)
    s3_arg = BigInt_clone(x, BigInt_strlen(x) + 1);
    BigInt_subtract_int(s3_arg, 3);
    s3 = f(s3_arg);
    BigInt_multiply_int(s3, 5);


    // 3 * x ** 4
    s4 = BigInt_construct(3);
    BigInt_multiply(s4, x);
    BigInt_multiply(s4, x);
    BigInt_multiply(s4, x);
    BigInt_multiply(s4, x);


    BigInt_add(res, s1);
    BigInt_add(res, s2);
    BigInt_subtract(res, s3);
    BigInt_add(res, s4);


    // BigInt_free(s1); // oh, just a subtle memory leak
    BigInt_free(s2);
    BigInt_free(s3);
    BigInt_free(s4);
    BigInt_free(s1_arg);
    BigInt_free(s2_arg);
    BigInt_free(s3_arg);
    return res;
}

BigInt* BigInt_mod(BigInt* a, BigInt* b) {
    BigInt* res = BigInt_clone(a, BigInt_strlen(a) + 1);

    while(BigInt_compare(res, b) >= 0) {
        if(BigInt_compare(res, b) == 0) {
            BigInt_free(res);
            return BigInt_construct(0);
        }

        BigInt_subtract(res, b);
    }

    return res;
}

// (b + (a % b)) % b
BigInt* BigInt_pymod(BigInt* a, BigInt* b) {
    BigInt* res = BigInt_clone(a, BigInt_strlen(a) + 1);
    BigInt* tmp = BigInt_mod(res, b);
    BigInt_add(tmp, b);
    BigInt_mod(tmp, b);

    BigInt_free(res);
    return tmp;
}


BigInt* calc(BigInt* arg) {
    BigInt* res = f(arg);

    if(BigInt_compare_int(arg, 100) <= 0) {
        return res;
    }

    BigInt* mod = BigInt_from_string(mod_str);
    BigInt* correction = BigInt_from_string(correction_str);

    BigInt* tmp = BigInt_pymod(res, mod);
    BigInt_add(tmp, correction);

    BigInt_free(mod);
    BigInt_free(correction);
    BigInt_free(res);
    return tmp;
}

int main(int argc, char* argv[]) {
    if(argc != 2) {
        fprintf(stderr, "Usage: %s <number>\n", argv[0]);
        return 1;
    }

    BigInt* arg = BigInt_from_string(argv[1]);
    if(arg == NULL) {
        fprintf(stderr, "Invalid number: %s\n", argv[1]);
        return 1;
    }
    if(BigInt_compare_int(arg, 0) < 0) {
        fprintf(stderr, "Invalid number: %s\n", argv[1]);
        BigInt_free(arg);
        return 1;
    }

    printf("allocating memory... lots... of... memory...\n");
    sleep(3);
    printf("warming up the CPU...\n");
    sleep(3);
    printf("increasing fan speed...\n");
    sleep(3);
    printf("calculating...\n");

    BigInt* res = calc(arg);
    char *flag = BigInt_to_new_string(res);
    printf("flag: %s\n", flag);
    BigInt_free(res);
    BigInt_free(arg);
    free(flag);
    return 0;
}
