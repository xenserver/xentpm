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

int generate_aik(char *aik_blob_file) 
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_HKEY hAIK;
    TSS_HKEY hPCA;
    TSS_HPOLICY	hTPMPolicy;
    TSS_HPOLICY	hSrkPolicy;
    TSS_HPOLICY	hAIKPolicy;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    BYTE n[2048/8];
    FILE *f_out;
    UINT32 initFlags;
    BYTE *blob;
    UINT32 blobLen;
    RSA	*aikRsa;
    EVP_PKEY *aikPk;
    UINT32 e_size;
    BYTE *e;
    int i, result;

    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        return result;
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
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByUUID(TSS_PS_TYPE_SYSTEM, SRK_UUID) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetPolicyObject(SRK, TSS_POLICY_USAGE) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_PLAIN,
		strlen(OWNER_SECRET), (BYTE*)OWNER_SECRET); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_SetSecret(SRK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Context_GetTpmObject(hContext, &hTPM); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_GetTpmObject failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
		TSS_POLICY_USAGE, &hTPMPolicy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CreateObject(TSS_OBJECT_TYPE_POLICY) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_AssignToObject(hTPMPolicy, hTPM);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_AssignToObject(TPM) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN,
		strlen(OWNER_SECRET), (BYTE*)OWNER_SECRET); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_SetSecret failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }


    // Create dummy PCA key 
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
						 hAIK, TSS_ALG_AES,
						 &blobLen,
						 &blob);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_CollateIdentityRequest failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    Tspi_Context_FreeMemory(hContext, blob);

    // Output file with AIK blob for TPM future Use */
    // The output of this call is TPM_KEY(12) struct
    // Used for loading an AIK in TPM
    result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_KEY_BLOB,
		TSS_TSPATTRIB_KEYBLOB_BLOB, &blobLen, &blob); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(KEY_BLOB) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

	
    if ((f_out = fopen (aik_blob_file, "wb")) == NULL) {
        syslog(LOG_ERR, "Unable to open %s for output\n", aik_blob_file);
        return 1;
    }
    if (fwrite (blob, 1, blobLen, f_out) != blobLen) {
        syslog(LOG_ERR, "Unable to write to %s\n", aik_blob_file);
        return 1;
    }
    fclose (f_out);
    Tspi_Context_FreeMemory (hContext, blob);

    return 0;
}

//
// outputs the AIK PEM base 64 key to stdout
//
// Return values:
// 0x00000000 - success
// 0x00000003 - Bad parameter - usually means AIK blob is not valid
//
int get_aik_pem(char *aik_blob_file) 
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_HKEY hAIK;
    TSS_HKEY hPCA;
    TSS_HPOLICY	hTPMPolicy;
    TSS_HPOLICY	hSrkPolicy;
    TSS_HPOLICY	hAIKPolicy;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    BYTE *blob;
    UINT32 blobLen;
    RSA	*aikRsa;
    UINT32 e_size;
    BYTE *e;
    int i, result;
    FILE *f_blob;

    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        return result;
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
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByUUID(TYPE_SYSTEM, SRK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetPolicyObject(SRK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_PLAIN,
		strlen(OWNER_SECRET), (BYTE*)OWNER_SECRET); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_SetSecret(SRK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Context_GetTpmObject(hContext, &hTPM); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_GetTpmObject failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
		TSS_POLICY_USAGE, &hTPMPolicy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CreateObject(TYPE_POLICY) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_AssignToObject(hTPMPolicy, hTPM);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_AssignToObject(TPM) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN,
		strlen(OWNER_SECRET), (BYTE*)OWNER_SECRET);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_SetSecret(TPM) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }


    // Read AIK blob 
    if ((f_blob = fopen(aik_blob_file, "rb")) == NULL) {
        syslog(LOG_ERR, "Unable to open file %s\n", aik_blob_file);
        return 1;
    }
    fseek(f_blob, 0, SEEK_END);
    blobLen = ftell(f_blob);
    fseek(f_blob, 0, SEEK_SET);
    blob = malloc(blobLen);
    if (fread(blob, 1, blobLen, f_blob) != blobLen) {
        syslog(LOG_ERR, "Unable to readn file %s\n", aik_blob_file);
        return 1;
    }
    fclose (f_blob);

    result = Tspi_Context_LoadKeyByBlob(hContext, hSRK, blobLen, blob, &hAIK); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByBlob(AIK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }


    // Output AIK pub key and certs, preceded by 4-byte lengths 
    result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_RSAKEY_INFO,
		TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &blobLen, &blob); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(AIK, RSA_MODULUS) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

	
    result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_RSAKEY_INFO,
        TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &e_size, &e); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(AIK, RSA_EXPONENT) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }


    aikRsa = RSA_new();
    aikRsa->n = BN_bin2bn(blob, blobLen, NULL);
    aikRsa->e = BN_new();
    aikRsa->e = BN_bin2bn(e, e_size, NULL);
    
    PEM_write_RSA_PUBKEY(stdout, aikRsa);
    RSA_free(aikRsa);
    
    Tspi_Context_FreeMemory(hContext, blob);
    return 0;
}

//
// outputs the AIK TCPA base 64 key to stdout
//
// Return values:
// 0x00000000 - success
// 0x00000003 - Bad parameter - usually means AIK blob is not valid
//
int get_aik_tcpa(char *aik_blob_file) 
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_HKEY hAIK;
    TSS_HKEY hPCA;
    TSS_HPOLICY	hTPMPolicy;
    TSS_HPOLICY	hSrkPolicy;
    TSS_HPOLICY	hAIKPolicy;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    BYTE *blob;
    UINT32 blobLen;
    RSA	*aikRsa;
    UINT32 e_size;
    BYTE *e;
    int i, result;
    FILE *f_blob;

    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        return result;
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
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByUUID(TYPE_SYSTEM, SRK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetPolicyObject(SRK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_PLAIN,
		strlen(OWNER_SECRET), (BYTE*)OWNER_SECRET); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_SetSecret(SRK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Context_GetTpmObject(hContext, &hTPM); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_GetTpmObject failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
		TSS_POLICY_USAGE, &hTPMPolicy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CreateObject(TYPE_POLICY) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_AssignToObject(hTPMPolicy, hTPM);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_AssignToObject(TPM) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN,
		strlen(OWNER_SECRET), (BYTE*)OWNER_SECRET);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_SetSecret(TPM) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    // Read AIK blob 
    if ((f_blob = fopen(aik_blob_file, "rb")) == NULL) {
        syslog(LOG_ERR, "Unable to open file %s\n", aik_blob_file);
        return 1;
    }
    fseek(f_blob, 0, SEEK_END);
    blobLen = ftell(f_blob);
    fseek(f_blob, 0, SEEK_SET);
    blob = malloc(blobLen);
    if (fread(blob, 1, blobLen, f_blob) != blobLen) {
        syslog(LOG_ERR, "Unable to readn file %s\n", aik_blob_file);
        return 1;
    }
    fclose (f_blob);

    result = Tspi_Context_LoadKeyByBlob(hContext, hSRK, blobLen, blob, &hAIK);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByBlob(AIK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }


    // The purpose of this call is to get TCPA_PUBKEY
    // structure of the AIK
    // this is passed to user for create a challange
    result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_KEY_BLOB,
                TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &blobLen, &blob); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(AIK, PUBLIC_KEY) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    BIO *bmem, *b64;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, blob, blobLen);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    char *buff = (char*)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;
    BIO_free_all(b64);
    printf(buff);
    free(buff);

    Tspi_Context_FreeMemory(hContext, blob);
    return 0;
}

