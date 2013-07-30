/*
 * Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * *   Redistributions of source code must retain the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

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
    
    /* First check if the TPM is owned. 
     * If it is not owned then xentpm needs to take ownership
     */
    if (tpm_owned()) {
        // TPM is already owned so nothing to do.
        return TSS_SUCCESS;
    }
    
    syslog(LOG_INFO, "Taking ownership of the TPM.\n");

    if ((result = read_tpm_key(tpm_key, SHA_DIGEST_LENGTH)) != 0) {
        syslog(LOG_ERR, "TPM Key Not Found \n");
        goto out;
    }


    result = tpm_init_context(& context, &tpm_handle, &tpm_policy);

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x tpm_init_context %s \n", 
                result,Trspi_Error_String(result));
        goto free_context;
    }

    srk_attributes = TSS_KEY_TSP_SRK | TSS_KEY_AUTHORIZATION;
    result = Tspi_Context_CreateObject(context, TSS_OBJECT_TYPE_RSAKEY, 
		srk_attributes, &srk_handle);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_Context_CreateObject %s \n",
                result,Trspi_Error_String(result));
        goto free_context;
    }

    /* Set the SRK password */
    result = Tspi_GetPolicyObject(srk_handle, TSS_POLICY_USAGE, &srk_policy);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_GetPolicyObject %s \n", 
                result, Trspi_Error_String(result));
        goto free_context;
    }

    result = Tspi_Policy_SetSecret(srk_policy, TSS_SECRET_MODE_SHA1,
            (UINT32)(sizeof(tpm_key)), (BYTE*)tpm_key);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error Setting SRK Password %s \n", 
		Trspi_Error_String(result));
        goto free_context;
    }
    /* Take ownership of the TPM
     * We expect the TPM to have an EK so Passing the third arg as 0.
     */
    result = Tspi_TPM_TakeOwnership(tpm_handle, srk_handle, 0);

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_TPM_TakeOwnership (%s)\n", 
		result, Trspi_Error_String(result));
        goto free_context;
    }

    syslog(LOG_INFO, "XenServer now owns the TPM.\n");

    /* Unregister AIK if present from a pervious ownership */
    unregister_aik_uuid(context);

free_context:  
    tpm_free_context(context, tpm_policy);
out:
    return result;
}
