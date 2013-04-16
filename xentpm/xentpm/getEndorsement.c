#include "xentpm.h"

#define BSIZE   128

/* Definitions from section 7 of
 * TCG PC Client Specific Implementation Specification
 * For Conventional BIOS
 */
#define TCG_TAG_PCCLIENT_STORED_CERT            0x1001
#define TCG_TAG_PCCLIENT_FULL_CERT              0x1002
#define TCG_TAG_PCCLIENT_PART_SMALL_CERT        0x1003
#define TCG_FULL_CERT                           0
#define TCG_PARTIAL_SMALL_CERT                  1


int get_ek()
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_RESULT result;
    TSS_HKEY hPubek;
    UINT32 modulusLen;
    UINT32 e_size;
    BYTE *modulus;
    BYTE *e;
    RSA *ekRsa;
    TSS_HPOLICY ekPolicy;
    BYTE tpm_key[KEY_SIZE];    

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
        syslog(LOG_ERR, "Error 0x%x on Tspi_Context_Create Unable to connect\n", result);
        return result;
    }

    result = Tspi_Context_Connect(hContext, NULL);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_Context_Connect Unable to connect\n", result);
        return result;
    }

    result = Tspi_Context_GetTpmObject (hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_Context_GetTpmObject\n", result);
        return result;
    }

    result = Tspi_TPM_GetPubEndorsementKey (hTPM, FALSE, NULL, &hPubek);
    if (result == TCPA_E_DISABLED_CMD) {

        result = Tspi_GetPolicyObject (hTPM, TSS_POLICY_USAGE, &ekPolicy);
        if (result != TSS_SUCCESS) {
            syslog(LOG_ERR, "Error 0x%x on Tspi_Context_GetTpmObject\n", result);
            return result;
        }

        result = Tspi_Policy_SetSecret(ekPolicy, TSS_SECRET_MODE_SHA1,
                     (UINT32)(sizeof(tpm_key)),(BYTE*)tpm_key);

        if (result != TSS_SUCCESS) {
            syslog(LOG_ERR, "Error Setting TPM Password %s \n", Trspi_Error_String(result));
            return result;
        } 
        result = Tspi_TPM_GetPubEndorsementKey (hTPM, TRUE, NULL, &hPubek);
    }

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error Reading TPM EK 0x%x (%s) \n", result, Trspi_Error_String(result));
        syslog(LOG_ERR, "Error Reading TPM EK, check the owner password after enabling the TPM \n");
        return result;
    }

    result = Tspi_GetAttribData (hPubek, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &modulusLen, &modulus);

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error TPM EK RSA %s \n", Trspi_Error_String(result));
        return result;
    }

    if (modulusLen != 256) {
        Tspi_Context_FreeMemory (hContext, modulus);
        syslog(LOG_ERR, "Error TPM EK RSA %s \n", Trspi_Error_String(result));
        return 1;
    }

    result = Tspi_GetAttribData(hPubek, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &e_size, &e);

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_Context_GetAttr Exponent\n", result);
        Tspi_Context_FreeMemory(hContext, modulus);
        return result;
    }

    Tspi_Context_CloseObject (hContext, hPubek);
    ekRsa = RSA_new();
    ekRsa->n = BN_bin2bn (modulus, modulusLen, NULL);
    ekRsa->e = BN_new();
    ekRsa->e = BN_bin2bn(e, e_size, NULL);

    Tspi_Context_FreeMemory (hContext, modulus);
    Tspi_Context_FreeMemory (hContext, e);

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

    PEM_write_RSA_PUBKEY(stdout, ekRsa);
    RSA_free(ekRsa);
    return 0;
}

int get_ekcert()
{
    TSS_HCONTEXT hContext;
    TSS_HNVSTORE hNV;
    UINT32 blobLen;
    UINT32 nvIndex = TSS_NV_DEFINED|TPM_NV_INDEX_EKCert;
    UINT32 offset;
    UINT32 ekOffset;
    UINT32 ekbufLen;
    BYTE *ekbuf;
    BYTE *blob;
    UINT32 tag, certType;
    int result;
    BYTE tpm_key[KEY_SIZE];    

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
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNV);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_CreateObject(TSS_OBJECT_TYPE_NV) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }
    result = Tspi_SetAttribUint32(hNV, TSS_TSPATTRIB_NV_INDEX, 0, nvIndex);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_SetAttribUint32 failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }


    /* Try reading certificate header from NV memory */
    blobLen = 5;
    result = Tspi_NV_ReadValue(hNV, 0, &blobLen, &blob);
   
    if (result != TSS_SUCCESS) {
        /* Try again with authorization */
        TSS_HPOLICY	hNVPolicy;
        result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hNVPolicy); 
        if (result != TSS_SUCCESS) {
            syslog(LOG_ERR, "Tspi_Context_CreateObject(TSS_OBJECT_TYPE_POLICY) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
        }

        result = Tspi_Policy_SetSecret(hNVPolicy, TSS_SECRET_MODE_SHA1,
                   (UINT32)(sizeof(tpm_key)),(BYTE*)tpm_key);
        if (result != TSS_SUCCESS) {
            syslog(LOG_ERR, "Tspi_Policy_SetSecret failed with 0x%X %s", result, Trspi_Error_String(result));
            return result;
        }

        result = Tspi_Policy_AssignToObject(hNVPolicy, hNV);
        if (result != TSS_SUCCESS) {
            syslog(LOG_ERR, "Tspi_Policy_AssignToObject failed with 0x%X %s", result, Trspi_Error_String(result));
            return result;
        }

        blobLen = 5;
        result = Tspi_NV_ReadValue(hNV, 0, &blobLen, &blob);
    }
    
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_NV_ReadValue failed with 0x%X %s", result, Trspi_Error_String(result));
        syslog(LOG_ERR, "Unable to read EK Certificate from TPM\n");
        return result;
    }
    if (blobLen < 5)
        goto parseerr;
    
    tag = (blob[0]<<8) | blob[1];
    
    if (tag != TCG_TAG_PCCLIENT_STORED_CERT)
        goto parseerr;
    
    certType = blob[2];
    
    if (certType != TCG_FULL_CERT)
        goto parseerr;
    
    ekbufLen = (blob[3]<<8) | blob[4];
    /*	result = Tspi_Context_FreeMemory (hContext, blob); CKERR; */
    offset = 5;
    blobLen = 2;
    result = Tspi_NV_ReadValue(hNV, offset, &blobLen, &blob); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_NV_ReadValue failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }
    
    if (blobLen < 2)
        goto parseerr;
    
    tag = (blob[0]<<8) | blob[1];
    
    if (tag == TCG_TAG_PCCLIENT_FULL_CERT) {
        offset += 2;
        ekbufLen -= 2;
    } else if (blob[0] != 0x30)	{ /* Marker of cert structure */
            goto parseerr;
    }

    /* Read cert from chip in pieces - too large requests may fail */
    ekbuf = malloc(ekbufLen);
    ekOffset = 0;
    while (ekOffset < ekbufLen) {
        blobLen = ekbufLen-ekOffset;
        if (blobLen > BSIZE)
            blobLen = BSIZE;
        result = Tspi_NV_ReadValue(hNV, offset, &blobLen, &blob); 
        if (result != TSS_SUCCESS) {
            syslog(LOG_ERR, "Tspi_NV_ReadValue failed with 0x%X %s", result, Trspi_Error_String(result));
            return result;
        }

        memcpy (ekbuf+ekOffset, blob, blobLen);
        /*		result = Tspi_Context_FreeMemory (hContext, blob); CKERR; */
        offset += blobLen;
        ekOffset += blobLen;
    }

    /*BIO *bmem, *b64;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, ekbuf, ekbufLen);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    char *buff = (char*)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;
    BIO_free_all(b64);
    printf(buff);
    free(buff);*/

    if ((result = print_base64(ekbuf,ekbufLen)) != 0) {
        syslog(LOG_ERR, "Error in converting B64 %s and %d ",__FILE__,__LINE__);
        return 1;
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

    return 0;

parseerr:
    syslog(LOG_ERR, "Failure, unable to parse certificate store structure\n");
    return 2;
}
