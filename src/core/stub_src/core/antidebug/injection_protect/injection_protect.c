#include "injection_protect.h"
#include "../../winapi/structs.h"
#include "../../winapi/imports.h"
#include "../../peb/peb.h"

int setProcessMitigationCodePolicy(void) {
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy;
    policy.DUMMYUNIONNAME.Flags = 0; 
    policy.DUMMYUNIONNAME.DUMMYSTRUCTNAME.MicrosoftSignedOnly = 1;
    SetProcessMitigationPolicy_t SetProcessMitigationPolicy = (SetProcessMitigationPolicy_t)pebget(L"kernelbase.dll", "SetProcessMitigationPolicy");
    if (!SetProcessMitigationPolicy) return -1;
    return SetProcessMitigationPolicy(8, &policy, sizeof(policy));
}