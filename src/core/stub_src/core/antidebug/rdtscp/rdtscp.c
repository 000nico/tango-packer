#include "../../winapi/constants.h"

int rdtscp_check(void) {
    unsigned int  aux;
    unsigned int  lo1, hi1, lo2, hi2;

    __asm__ __volatile__ ("rdtscp" : "=a"(lo1), "=d"(hi1), "=c"(aux));
    __asm__ __volatile__ ("nop");
    __asm__ __volatile__ ("rdtscp" : "=a"(lo2), "=d"(hi2), "=c"(aux));

    unsigned long long t1 = ((unsigned long long)hi1 << 32) | lo1;
    unsigned long long t2 = ((unsigned long long)hi2 << 32) | lo2;

    if ((t2 - t1) > RDTSCP_THRESHOLD)
        return 1;

    return 0;
}
