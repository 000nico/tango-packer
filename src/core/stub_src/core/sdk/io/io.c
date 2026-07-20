#include "io.h"
#include "../../peb/peb.h"
#include "../../winapi/imports.h"
#include "../strings/strings.h"

#define STD_OUTPUT_HANDLE ((unsigned int)-11)

void my_puts(const char* str) {
    GetStdHandle_t myGetStdHandle = (GetStdHandle_t)pebget(L"kernel32.dll", "GetStdHandle");
    WriteFile_t myWriteFile = (WriteFile_t)pebget(L"kernel32.dll", "WriteFile");

    if (!myGetStdHandle || !myWriteFile) return;

    void* hConsole = myGetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == (void*)-1 || hConsole == 0) return;

    unsigned int len = (unsigned int)my_strlen(str);
    unsigned int written = 0;
    
    myWriteFile(hConsole, str, len, &written, 0);
    myWriteFile(hConsole, "\n", 1, &written, 0);
}
