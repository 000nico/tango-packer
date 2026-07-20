#include "../winapi/imports.h"

#ifndef VEH_H
#define VEH_H

void start_veh();
long handler(struct _EXCEPTION_POINTERS* ExceptionInfo);

#endif // VEH_H