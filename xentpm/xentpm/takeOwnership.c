#include "xentpm.h"

/*
* Read the /sys/class/misc/tpm0/device/owned file.
* If it contains a 0, then the TPM is not owned.
* If it contains a 1, then the TPM is owned.
*/
int tpm_owned()
{
    int owned = 0;  // assume unowned
    FILE *file;
    char c;
    errno = 0;
    
    /* Currently trousers does not support multiple TPMs
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
    TSS_HCONTEXT context;
    TSS_HTPM tpm_handle;
    TSS_RESULT result;
    TSS_HPOLICY tpm_policy;
    TSS_HKEY srk_handle;
    TSS_HPOLICY srk_policy;
    TSS_FLAG srk_attributes;
    BYTE tpm_key[SHA_DIGEST_LENGTH];    
    syslog(LOG_INFO, "Taking ownership of the TPM.\n");


    /* First check if the TPM is owned. 
     * iF it is not owned then xentpm needs to take ownership
     */
    if (tpm_owned()) {
        // TPM is already owned so nothing to do.
        syslog(LOG_INFO, "TPM is already owned.\n");
        return 0;
    }

    if ((result = read_tpm_key(tpm_key,SHA_DIGEST_LENGTH)) != 0) {
        syslog(LOG_ERR, "TPM Key Not Found \n");
        return TSS_E_FAIL;
    }


    result = tpm_init_context(& context, &tpm_handle, &tpm_policy);

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x tpm_init_context %s \n", 
                result,Trspi_Error_String(result));
        return result;
    }

    srk_attributes = TSS_KEY_TSP_SRK | TSS_KEY_AUTHORIZATION;
    result = Tspi_Context_CreateObject(context, TSS_OBJECT_TYPE_RSAKEY, srk_attributes, &srk_handle);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_Context_CreateObject %s \n",
                result,Trspi_Error_String(result));
        return result;
    }

    /* Set the SRK password */
    result = Tspi_GetPolicyObject(srk_handle, TSS_POLICY_USAGE, &srk_policy);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_GetPolicyObject %s \n", 
                result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_SetSecret(srk_policy, TSS_SECRET_MODE_SHA1,
            (UINT32)(sizeof(tpm_key)),(BYTE*)tpm_key);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error Setting SRK Password %s \n", Trspi_Error_String(result));
        return result;
    }
    /* Take ownership of the TPM
     * We expect the TPM to have an EK so Passing the third arg as 0.
     */
    result = Tspi_TPM_TakeOwnership(tpm_handle, srk_handle, 0);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_TPM_TakeOwnership (%s)\n", result, Trspi_Error_String(result));
        return result;
    }

    syslog(LOG_INFO, "XenServer now owns the TPM.\n");

    return 0;
}
