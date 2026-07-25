int peb_check(void) {
    unsigned char* peb;

    __asm__ __volatile__ (
        "movq %%gs:0x60, %0"
        : "=r" (peb)
    );

    unsigned int ntGlobalFlag = *(unsigned int*)(peb + 0xBC);

    if (ntGlobalFlag == 0x70) return 1;
    return 0;
}
