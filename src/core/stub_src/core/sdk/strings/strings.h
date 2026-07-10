#define UNICODE_STR(x) L ## x

int my_strcmp(const char* a, const char* b);
unsigned long my_strlen(const char* s);
int my_wcscmp(unsigned short* a, unsigned short* b);