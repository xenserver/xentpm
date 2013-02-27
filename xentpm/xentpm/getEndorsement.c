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

    result = take_ownership();
    if (result) {
        log_msg(__FILE__,__LINE__,"Error 0x%X taking ownership of TPM.\n", result);
        exit_status(result);
    }

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

    result = Tspi_Context_GetTpmObject (hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_Context_GetTpmObject\n", result);
        exit_status(result);
    }

    result = Tspi_TPM_GetPubEndorsementKey (hTPM, FALSE, NULL, &hPubek);
    if (result == TCPA_E_DISABLED_CMD) {

        result = Tspi_GetPolicyObject (hTPM, TSS_POLICY_USAGE, &ekPolicy);
        if (result != TSS_SUCCESS) {
            log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_Context_GetTpmObject\n", result);
            exit_status(result);
        }

        result = Tspi_Policy_SetSecret(ekPolicy, TSS_SECRET_MODE_PLAIN,
                (UINT32)strlen(OWNER_SECRET),(BYTE*)OWNER_SECRET);

        if (result != TSS_SUCCESS) {
            log_msg(__FILE__,__LINE__,"Error Setting TPM Password %s \n", Trspi_Error_String(result));
            exit_status(result);
        } 
        result = Tspi_TPM_GetPubEndorsementKey (hTPM, TRUE, NULL, &hPubek);
    }

    if (result != TSS_SUCCESS) {
            log_msg(__FILE__,__LINE__,"Error Reading TPM EK 0x%x (%s) \n", result, Trspi_Error_String(result));
            log_msg(__FILE__,__LINE__,"Error Reading TPM EK, check the owner password after enabling the TPM \n");
	        exit_status(1);
    }

    result = Tspi_GetAttribData (hPubek, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &modulusLen, &modulus);

    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error TPM EK RSA %s \n", Trspi_Error_String(result));
        return 1;
    }

    if (modulusLen != 256) {
        Tspi_Context_FreeMemory (hContext, modulus);
        log_msg(__FILE__,__LINE__,"Error TPM EK RSA %s \n", Trspi_Error_String(result));
        return 1;
    }

    result = Tspi_GetAttribData(hPubek, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &e_size, &e);

    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_Context_GetAttr Exponent\n", result);
        Tspi_Context_FreeMemory (hContext, modulus);
        return 1;
    }

    Tspi_Context_CloseObject (hContext, hPubek);
    ekRsa = RSA_new();
    ekRsa->n = BN_bin2bn (modulus, modulusLen, NULL);
    ekRsa->e = BN_new();
    ekRsa->e = BN_bin2bn(e, e_size, NULL);

    Tspi_Context_FreeMemory (hContext, modulus);
    Tspi_Context_FreeMemory (hContext, e);

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

    result = take_ownership();
    if (result) {
        log_msg(__FILE__,__LINE__,"Error 0x%X taking ownership of TPM.\n", result);
        exit_status(result);
    }

    result = Tspi_Context_Create(&hContext); CKERR;
    result = Tspi_Context_Connect(hContext, NULL); CKERR;
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNV); CKERR;
    result = Tspi_SetAttribUint32(hNV, TSS_TSPATTRIB_NV_INDEX, 0, nvIndex); CKERR;

    /* Try reading certificate header from NV memory */
    blobLen = 5;
    result = Tspi_NV_ReadValue(hNV, 0, &blobLen, &blob);
   
    if (result != TSS_SUCCESS) {
        /* Try again with authorization */
        TSS_HPOLICY	hNVPolicy;
        result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hNVPolicy); CKERR;
        result = Tspi_Policy_SetSecret(hNVPolicy,TSS_SECRET_MODE_PLAIN,
                (UINT32)strlen(OWNER_SECRET),(BYTE*)OWNER_SECRET);
        result = Tspi_Policy_AssignToObject(hNVPolicy, hNV); CKERR;
        blobLen = 5;
        result = Tspi_NV_ReadValue(hNV, 0, &blobLen, &blob);
    }
    
    if (result != TSS_SUCCESS) {
        // printf("Error %s\n",Trspi_Error_String(result));
        log_msg(__FILE__,__LINE__,"Unable to read EK Certificate from TPM\n");
        goto error;
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
    result = Tspi_NV_ReadValue(hNV, offset, &blobLen, &blob); CKERR;
    
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
        result = Tspi_NV_ReadValue(hNV, offset, &blobLen, &blob); CKERR;
        memcpy (ekbuf+ekOffset, blob, blobLen);
        /*		result = Tspi_Context_FreeMemory (hContext, blob); CKERR; */
        offset += blobLen;
        ekOffset += blobLen;
    }

    BIO *bmem, *b64;
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
    free(buff);

    result = Tspi_Context_Close(hContext);CKERR;
    return 0;

error:
    log_msg(__FILE__,__LINE__,"Failure, error code: %s\n", Trspi_Error_String(result));
    return 1;
parseerr:
    log_msg(__FILE__,__LINE__,"Failure, unable to parse certificate store structure\n");
    return 2;
}
