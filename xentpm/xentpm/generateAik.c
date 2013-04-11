/*
 *generate AI
 *      Publish AIK public key in PEM format and TCPA blob format
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
#include <unistd.h>

int tpm_aik_context(TSS_HCONTEXT *hContext, TSS_HTPM *hTPM, TSS_HKEY *hSRK,
        TSS_HPOLICY *hTPMPolicy, TSS_HPOLICY *hSrkPolicy) 
{

    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    int result;

    result = Tspi_Context_Create(hContext); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_Create failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }
    result = Tspi_Context_Connect((*hContext), NULL);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_Connect failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }
    result = Tspi_Context_LoadKeyByUUID((*hContext),
            TSS_PS_TYPE_SYSTEM, SRK_UUID, hSRK);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByUUID(TSS_PS_TYPE_SYSTEM, SRK_UUID) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_GetPolicyObject((*hSRK), TSS_POLICY_USAGE, hSrkPolicy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetPolicyObject(SRK, TSS_POLICY_USAGE) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_SetSecret((*hSrkPolicy), TSS_SECRET_MODE_PLAIN,
            strlen(OWNER_SECRET), (BYTE*)OWNER_SECRET); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_SetSecret(SRK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Context_GetTpmObject((*hContext), hTPM); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_GetTpmObject failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Context_CreateObject((*hContext), TSS_OBJECT_TYPE_POLICY,
            TSS_POLICY_USAGE, hTPMPolicy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CreateObject(TSS_OBJECT_TYPE_POLICY) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_AssignToObject((*hTPMPolicy), (*hTPM));
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_AssignToObject(TPM) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_SetSecret((*hTPMPolicy), TSS_SECRET_MODE_PLAIN,
            strlen(OWNER_SECRET), (BYTE*)OWNER_SECRET); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_SetSecret failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    return TSS_SUCCESS;
}

int tpm_aik_context_free(TSS_HCONTEXT hContext,
        TSS_HPOLICY hTPMPolicy)
{
    int result ;
    result = Tspi_Context_CloseObject(hContext,hTPMPolicy);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CloseObject failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }
    result = Tspi_Context_FreeMemory (hContext,NULL);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_FreeMemory failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }
    result = Tspi_Context_Close(hContext);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_Close failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }
    return TSS_SUCCESS;
}

int generate_aik(char *aik_blob_path) 
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_HKEY hAIK;
    TSS_HKEY hPCA;
    TSS_HPOLICY	hTPMPolicy;
    TSS_HPOLICY	hSrkPolicy;
    BYTE n[2048/8];
    FILE *f_out;
    BYTE* tcpaiIdblob;
    UINT32 tcpaiIdlobLen;
    BYTE*  attrKeyblob;
    UINT32 attrKeyblobLen;
    int  result;

    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        return result;
    }
    
    if (access("/opt/xensource/tpm/aiktpmblob",R_OK)) {
        syslog(LOG_INFO, "Take Ownership aikblob already present \n");
    }

    result = tpm_aik_context(&hContext, &hTPM, &hSRK, 
            &hTPMPolicy, &hSrkPolicy); 

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error in aik context for generating aik");
        return result;
    }

    // Create dummy PCA key 
    // use XenServer Public Key 
    result = Tspi_Context_CreateObject(hContext,
            TSS_OBJECT_TYPE_RSAKEY,
            TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048,
            &hPCA);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CreateObject(RSAKEY, TSS_KEY_TYPE_LEGACY) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    memset (n, 0xff, sizeof(n));
    result = Tspi_SetAttribData(hPCA, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, sizeof(n), n); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_SetAttribData(PCA, RSAKEY_INFO) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }


    // Create AIK object 
    result = Tspi_Context_CreateObject(hContext,
            TSS_OBJECT_TYPE_RSAKEY,
            TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048, &hAIK);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_CreateObject(RSAKEY, TSS_KEY_TYPE_IDENTITY) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }


    // Generate new AIK 
    result = Tspi_TPM_CollateIdentityRequest(hTPM, hSRK, hPCA, 0, "",
            hAIK, TSS_ALG_AES, &tcpaiIdlobLen, &tcpaiIdblob);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_CollateIdentityRequest failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    Tspi_Context_FreeMemory(hContext, tcpaiIdblob);

    // Output file with AIK blob for TPM future Use */
    // The output of this call is TPM_KEY(12) struct
    // Used for loading an AIK in TPM
    result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_KEY_BLOB,
            TSS_TSPATTRIB_KEYBLOB_BLOB, &attrKeyblobLen, &attrKeyblob); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(KEY_BLOB) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }


    if ((f_out = fopen (aik_blob_path, "wb")) == NULL) {
        syslog(LOG_ERR, "Unable to open %s for output\n", aik_blob_path);
        return 1;
    }
    if (fwrite (attrKeyblob, 1, attrKeyblobLen, f_out) != attrKeyblobLen) {
        syslog(LOG_ERR, "Unable to write to %s\n", aik_blob_path);
        return 1;
    }
    fclose (f_out);

    //free all memory with this context
    //close context object
    result = Tspi_Context_CloseObject(hContext,hAIK);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CloseObject failed  0x%X %s", result, Trspi_Error_String(result));
        return result;
    }
    result = Tspi_Context_CloseObject(hContext,hPCA);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CloseObject failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = tpm_aik_context_free(hContext,hTPMPolicy);

    if (result != TSS_SUCCESS ) {
        syslog(LOG_ERR, "Error in aik context for free %s and %d ",__FILE__,__LINE__);
        return result;
    }

    return 0;
}



//
// outputs the AIK PEM base 64 key to stdout
//
// Return values:
// 0x00000000 - success
// 0x00000003 - Bad parameter - usually means AIK blob is not valid
//
int get_aik_pem(char *aik_blob_path) 
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_HKEY hAIK;
    TSS_HPOLICY	hTPMPolicy;
    TSS_HPOLICY	hSrkPolicy;
    BYTE *aikblob;
    UINT32 aikblobLen;
    RSA	*aikPubKey;
    UINT32 keyExponentSize;
    BYTE *keyExponent;
    int  result;
    FILE *f_blob;

    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        return result;
    }

    result = tpm_aik_context(&hContext, &hTPM, &hSRK, 
            &hTPMPolicy, &hSrkPolicy); 

    if(result != TSS_SUCCESS ) {
        syslog(LOG_ERR, "Error in aik context for generating aik_pem");
        return result;
    }

    // Read AIK blob 
    if ((f_blob = fopen(aik_blob_path, "rb")) == NULL) {
        syslog(LOG_ERR, "Unable to open file %s\n", aik_blob_path);
        return 1;
    }
    fseek(f_blob, 0, SEEK_END);
    aikblobLen = ftell(f_blob);
    fseek(f_blob, 0, SEEK_SET);
    aikblob = malloc(aikblobLen);

    if (!aikblob) {
        syslog(LOG_ERR, "Malloc failed in %s and %d ",__FILE__,__LINE__);
        return 1;
    }

    if (fread(aikblob, 1, aikblobLen, f_blob) != aikblobLen) {
        syslog(LOG_ERR, "Unable to readn file %s\n", aik_blob_path);
        return 1;
    }
    fclose (f_blob);

    result = Tspi_Context_LoadKeyByBlob(hContext, hSRK, aikblobLen, aikblob, &hAIK); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByBlob(AIK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }


    // Aik pub key read from the blob 
    result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &aikblobLen, &aikblob); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(AIK, RSA_MODULUS) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }


    result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &keyExponentSize, &keyExponent); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(AIK, RSA_EXPONENT) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }


    aikPubKey = RSA_new();
    aikPubKey->n = BN_bin2bn(aikblob, aikblobLen, NULL);
    aikPubKey->e = BN_bin2bn(keyExponent,keyExponentSize, NULL);

    PEM_write_RSA_PUBKEY(stdout, aikPubKey);
    RSA_free(aikPubKey);

    result = tpm_aik_context_free(hContext,hTPMPolicy);

    if (result != TSS_SUCCESS ) {
        syslog(LOG_ERR, "Error in aik context for free %s and %d ",__FILE__,__LINE__);
        return result;
    }
    return 0;
}

//
// outputs the AIK TCPA base 64 key to stdout
//
// Return values:
// 0x00000000 - success
// 0x00000003 - Bad parameter - usually means AIK blob is not valid
//
int get_aik_tcpa(char *aik_blob_path) 
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_HKEY hAIK;
    TSS_HPOLICY	hTPMPolicy;
    TSS_HPOLICY	hSrkPolicy;
    BYTE *aikblob;
    UINT32 aikblobLen;
    BYTE *tcpaKeyblob;
    UINT32 tcpaKeyblobLen;
    int  result;
    FILE *f_blob;

    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        return result;
    }
    result = tpm_aik_context(&hContext, &hTPM, &hSRK, 
            &hTPMPolicy, &hSrkPolicy); 

    if(result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error in aik context for generating aik tcpa");
        return result;
    }

    // Read AIK blob 
    if ((f_blob = fopen(aik_blob_path, "rb")) == NULL) {
        syslog(LOG_ERR, "Unable to open file %s\n", aik_blob_path);
        return 1;
    }
    fseek(f_blob, 0, SEEK_END);
    aikblobLen = ftell(f_blob);
    fseek(f_blob, 0, SEEK_SET);
    aikblob = malloc(aikblobLen);
    if (fread(aikblob, 1, aikblobLen, f_blob) != aikblobLen) {
        syslog(LOG_ERR, "Unable to readn file %s\n", aik_blob_path);
        return 1;
    }
    fclose (f_blob);

    result = Tspi_Context_LoadKeyByBlob(hContext, hSRK, aikblobLen, aikblob, &hAIK);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByBlob(AIK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }


    // The purpose of this call is to get TCPA_PUBKEY
    // structure of the AIK
    // this is passed to user for creating a challange
    result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_KEY_BLOB,
            TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &tcpaKeyblobLen, &tcpaKeyblob); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(AIK, PUBLIC_KEY) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

   /* BIO *bmem, *b64;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, tcpaKeyblob, tcpaKeyblobLen);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    char *buff = (char*)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;
    BIO_free_all(b64);
    printf(buff);
    free(buff);*/
    
    if ((result = print_base64(tcpaKeyblob,tcpaKeyblobLen)) != 0) {
        syslog(LOG_ERR, "Error in converting B64 %s and %d ",__FILE__,__LINE__);
        return 1;
    }
    
    result = tpm_aik_context_free(hContext,hTPMPolicy);

    if (result != TSS_SUCCESS ) {
        syslog(LOG_ERR, "Error in aik context for free %s and %d ",__FILE__,__LINE__);
        return result;
    }

    return 0;
}

int print_base64(void* data, UINT32 len)
{

    BIO *bmem, *b64;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, data, len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    char *b64Buff = (char*)malloc(bptr->length);
    
    if (!b64Buff) {
        syslog(LOG_ERR, "Error in aik context for free %s and %d ",__FILE__,__LINE__);
        return 1;
    } 
    memcpy(b64Buff, bptr->data, bptr->length-1);
    b64Buff[bptr->length-1] = 0;
    BIO_free_all(b64);
    printf(b64Buff);
    free(b64Buff);
    return 0;
}

