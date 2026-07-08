void unencrypt(unsigned char *text_ptr, unsigned int text_size, unsigned long long key) {
    unsigned char xor_key = (unsigned char)(key & 0xFF);

    for (unsigned int i = 0; i < text_size; i++) {
        text_ptr[i] ^= xor_key;
    }
}