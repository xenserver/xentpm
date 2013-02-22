#include "xentpm.h"

#define CKERR if (result != TSS_SUCCESS) { log_msg(__FILE__,__LINE__,"Failure, error code: 0x%x %s \n", result,Trspi_Error_String(result)); return 1; }

//
// Read the /sys/class/misc/tpm0/device/owned file.
// If it contains a 0, then the TPM is not owned.
// If it contains a 1, then the TPM is owned.
//
int tpm_owned()
{
    int owned = 0;  // assume unowned
    FILE *file;
    char c;

    errno = 0;
    file = fopen("/sys/class/misc/tpm0/device/owned", "r");
    if (!file) {
        return owned;
    } 

    c = fgetc(file);
    if (c != 0) {
        log_msg(__FILE__,__LINE__,"/sys/class/misc/tpm0/device/owned contains %c\n", c);

        if (c == '1') {
            owned = 1;
        }
    }

    fclose(file);

    if (!owned) {
        log_msg(__FILE__,__LINE__,"The TPM is not owned.\n");
    }

    return owned;
}

int take_ownership()
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_RESULT result;
    TSS_HPOLICY tpmPolicy;
    TSS_HKEY hSRK;
    TSS_HPOLICY srkPolicy;
    TSS_FLAG fSrkAttrs;

    log_msg(__FILE__,__LINE__,"Taking ownership of the TPM.\n");

    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_Context_Create Unable to connect\n", result);
        exit_status(result);
    }

    result = Tspi_Context_Connect(hContext, NULL);
    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_Context_Connect Unable to connect\n", result);
        exit_status(result);
    }

    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_Context_GetTpmObject\n", result);
        exit_status(result);
    }

    //
    // Set the TPM password
    //
    result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &tpmPolicy);
    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_GetPolicyObject\n", result);
        exit_status(result);
    }

    result = Tspi_Policy_SetSecret(tpmPolicy, TSS_SECRET_MODE_PLAIN,
                (UINT32)strlen(OWNER_SECRET),(BYTE*)OWNER_SECRET);
    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error Setting TPM Password %s \n", Trspi_Error_String(result));
        exit_status(result);
    }

    fSrkAttrs = TSS_KEY_TSP_SRK | TSS_KEY_AUTHORIZATION;
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, fSrkAttrs, &hSRK);
    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_Context_CreateObject\n", result);
        exit_status(result);
    }

    //
    // Set the SRK password
    //
    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkPolicy);
    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_GetPolicyObject\n", result);
        exit_status(result);
    }

    result = Tspi_Policy_SetSecret(srkPolicy, TSS_SECRET_MODE_PLAIN,
                (UINT32)strlen(OWNER_SECRET),(BYTE*)OWNER_SECRET);
    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error Setting SRK Password %s \n", Trspi_Error_String(result));
        exit_status(result);
    }

    //
    // Take ownership of the TPM
    //
    result = Tspi_TPM_TakeOwnership(hTPM, hSRK, 0);
    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_TPM_TakeOwnership (%s)\n", result, Trspi_Error_String(result));
        exit_status(result);
    }

    log_msg(__FILE__,__LINE__,"XenServer now owns the TPM.\n");

    return 0;
}
