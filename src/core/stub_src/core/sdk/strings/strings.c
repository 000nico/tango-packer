int my_strcmp(const char* a, const char* b) {
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

unsigned long my_strlen(const char* s) {
    const char* p = s;
    while (*p) p++;
    return (unsigned long)(p - s);
}

int my_wcscmp(unsigned short* a, unsigned short* b) {
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return (unsigned short)*a - (unsigned short)*b;
}

int my_wcsicmp(unsigned short* a, unsigned short* b) {
    while (*a && *b) {
        unsigned short ca = *a;
        unsigned short cb = *b;
        if (ca >= 'a' && ca <= 'z') ca -= 32;
        if (cb >= 'a' && cb <= 'z') cb -= 32;
        if (ca != cb) break;
        a++;
        b++;
    }
    unsigned short ca = *a;
    unsigned short cb = *b;
    if (ca >= 'a' && ca <= 'z') ca -= 32;
    if (cb >= 'a' && cb <= 'z') cb -= 32;
    return ca - cb;
}