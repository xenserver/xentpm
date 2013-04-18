/*
 * aikrespond.c
 *
 * Third step in proving an AIK is valid without using a Privacy CA.
 *
 * Reads AIK blob file and challenge file from challenger. Decrypts
 * encrypted data and outputs to a file, which should be sent back to
 * challenger. Successful decryption proves that it is a real AIK.
 */

/*
 * Copyright (c) 2009 Hal Finney
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "xentpm.h"
#include <arpa/inet.h>
int tpm_challenge(char *aik_blob_path, char *challenge)
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_HKEY hAIK;
    TSS_HPOLICY	hTPMPolicy;
    TSS_HPOLICY	hSrkPolicy;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    FILE *f_in;
    BYTE *response;
    UINT32 responseLen;
    BYTE *buf;
    UINT32 bufLen;
    BYTE *asym;
    UINT32 asymLen;
    BYTE *sym;
    UINT32 symLen;
    int	result;
    BIO *bmem, *b64;
    BYTE tpm_key[KEY_SIZE];    

    syslog(LOG_INFO, "Recieved a Challange");

    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        return result;
    }
    if ((result = read_tpm_key(tpm_key,KEY_SIZE)) != 0) {
        syslog(LOG_ERR, "TPM Key Not Found \n");
        return TSS_E_FAIL;
    }
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_Create failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Context_Connect(hContext, NULL); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_Connect failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Context_LoadKeyByUUID(hContext,
                TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByUUID(SRK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetPolicyObject(SRK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_SHA1,
                (UINT32)(sizeof(tpm_key)),(BYTE*)tpm_key);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_SetSecret(SRK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Context_GetTpmObject(hContext, &hTPM); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_GetTpmObject failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
                TSS_POLICY_USAGE, &hTPMPolicy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CreateObject(TPM_POLICY) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_AssignToObject(hTPMPolicy, hTPM);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_AssignToObject(TPM Policy) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_SHA1,
                (UINT32)(sizeof(tpm_key)),(BYTE*)tpm_key);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_SetSecret(TPM) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }


    if ( (result = load_aik_tpm(aik_blob_path, hContext,  hSRK, &hAIK)) != 0) {
        syslog(LOG_ERR, "Unable to readn file %s\n", aik_blob_path);
        return result;
    }

    // Base64 decode the challenge
    bufLen = strlen(challenge);
    BYTE* challengeBuf = (BYTE*)malloc(bufLen);
    memset(challengeBuf, 0, bufLen);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(challenge, bufLen);
    bmem = BIO_push(b64, bmem);
    int challengeLen = BIO_read(bmem, challengeBuf, bufLen);
    BIO_free_all(bmem);

    // Parse challenge
    if (challengeLen < 8)
        goto badchal;
    asymLen = ntohl(*(UINT32*)challengeBuf);
    asym = challengeBuf + 4;
    challengeBuf += asymLen + 4;
    if (challengeLen < asymLen+8)
        goto badchal;
    symLen = ntohl(*(UINT32*)challengeBuf);
    if (challengeLen != asymLen + symLen + 8)
        goto badchal;
    sym = challengeBuf + 4;

    // Decrypt challenge data
    result = Tspi_TPM_ActivateIdentity(hTPM, hAIK, asymLen, asym,
                                       symLen, sym,
                                       &responseLen, &response); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_TPM_ActivateIdentity failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    if ((result = print_base64(response,responseLen)) != 0) {
        syslog(LOG_ERR, "Error in converting B64 %s and %d ",__FILE__,__LINE__);
        return 1;
    }

    syslog(LOG_INFO, "Success in response!\n");
    return 0;

badchal:
    syslog(LOG_ERR, "Challenge file format is wrong\n");
    return 1;
}
