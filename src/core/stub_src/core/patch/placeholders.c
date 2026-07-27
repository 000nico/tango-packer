#include "placeholders.h"
#include "../crypto/chacha20.h"
volatile unsigned long long original_entry_point = 0xDEADBEEF;
volatile unsigned long long key = 0xCAFEBABE;

/*
volatile u32 KEY[2][4] = {
    { MAGIC, MAGIC, MAGIC, MAGIC },
    { MAGIC, MAGIC, MAGIC, MAGIC },
};
*/
