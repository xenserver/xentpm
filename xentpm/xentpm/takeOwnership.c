#include "xentpm.h"//
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
    
    /* Currently trousers does not support two TPMs
     * and the dev path is hardcoded to /dev/tpm0
     * Still the 'owned' property belongs to the driver and 
     * exposed via sysfs 
     * TCG/TCPA driver will always expose this property for dev0
     * Need to test on other drivers/ find a better way to do this.
     * 
     * */
    file = fopen("/sys/class/misc/tpm0/device/owned", "r");
    if (!file) {
        return owned;
    } 

    c = fgetc(file);
    if (c != 0) {
        if (c == '1') {
            owned = 1;
        }
    }

    fclose(file);

    if (!owned) {
        syslog(LOG_INFO, "The TPM is not owned.\n");
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
    BYTE tpm_key[KEY_SIZE];    
    syslog(LOG_INFO, "Taking ownership of the TPM.\n");
    
    
    //
    // First check if the TPM is owned.  If it is not owned then xentpm needs to take ownership
    //
    if (tpm_owned()) {
        // TPM is already owned so nothing to do.
        syslog(LOG_INFO, "TPM is already owned.\n");
        return 0;
    }

    if ((result = read_tpm_key(tpm_key,KEY_SIZE)) != 0) {
        syslog(LOG_ERR, "TPM Key Not Found \n");
        return TSS_E_FAIL;
    }
     
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_Context_Create Unable to connect\n", result);
        return result;
    }
    //Connect to Local Troursers URI=NULL
    result = Tspi_Context_Connect(hContext, NULL);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_Context_Connect Unable to connect\n", result);
        return result;
    }

    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        syslog(LOG_INFO, "Error 0x%x on Tspi_Context_GetTpmObject\n", result);
        return result;
    }

    //
    // Set the TPM password
    //
    result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &tpmPolicy);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_GetPolicyObject\n", result);
        return result;
    }

    //result = Tspi_Policy_SetSecret(tpmPolicy, TSS_SECRET_MODE_PLAIN,
      //          (UINT32)strlen(OWNER_SECRET),(BYTE*)OWNER_SECRET);
    result = Tspi_Policy_SetSecret(tpmPolicy, TSS_SECRET_MODE_SHA1,
                (UINT32)(sizeof(tpm_key)),(BYTE*)tpm_key);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error Setting TPM Password %s \n", Trspi_Error_String(result));
        return result;
    }

    fSrkAttrs = TSS_KEY_TSP_SRK | TSS_KEY_AUTHORIZATION;
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, fSrkAttrs, &hSRK);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_Context_CreateObject\n", result);
        return result;
    }

    //
    // Set the SRK password
    //
    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkPolicy);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_GetPolicyObject\n", result);
        return result;
    }

    //result = Tspi_Policy_SetSecret(srkPolicy, TSS_SECRET_MODE_PLAIN,
      //          (UINT32)strlen(OWNER_SECRET),(BYTE*)OWNER_SECRET);
    result = Tspi_Policy_SetSecret(srkPolicy, TSS_SECRET_MODE_SHA1,
                (UINT32)(sizeof(tpm_key)),(BYTE*)tpm_key);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error Setting SRK Password %s \n", Trspi_Error_String(result));
        return result;
    }
    //
    // Take ownership of the TPM
    // We expect the TPM to have an EK so Passing the third arg as 0.
    result = Tspi_TPM_TakeOwnership(hTPM, hSRK, 0);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_TPM_TakeOwnership (%s)\n", result, Trspi_Error_String(result));
        return result;
    }

    syslog(LOG_INFO, "XenServer now owns the TPM.\n");

    return 0;
}
