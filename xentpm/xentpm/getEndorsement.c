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
    TSS_HPOLICY	hTPMPolicy;
    TSS_HPOLICY	hSrkPolicy;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_RESULT result;
    TSS_HKEY hPubek;
    UINT32 modulusLen;
    UINT32 exponentLen;
    BYTE *modulus;
    BYTE *exponent;
    RSA *ekRsa;
    
    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        return result;
    }

    result = tpm_create_context(&hContext, &hTPM, &hSRK, 
            &hTPMPolicy, &hSrkPolicy); 

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error in aik context for generating ek");
        return result;
    }
    result = Tspi_TPM_GetPubEndorsementKey (hTPM, TRUE, NULL, &hPubek);

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

    if (modulusLen != TSS_DAA_LENGTH_N) {
        Tspi_Context_FreeMemory (hContext, modulus);
        syslog(LOG_ERR, "Error TPM EK RSA %s \n", Trspi_Error_String(result));
        return 1;
    }

    result = Tspi_GetAttribData(hPubek, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &exponentLen, &exponent);

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_Context_GetAttr Exponent\n", result);
        Tspi_Context_FreeMemory(hContext, modulus);
        return result;
    }

    Tspi_Context_CloseObject (hContext, hPubek);
    ekRsa = RSA_new();
    ekRsa->n = BN_bin2bn (modulus, modulusLen, NULL);
    ekRsa->e = BN_bin2bn(exponent, exponentLen, NULL);

    PEM_write_RSA_PUBKEY(stdout, ekRsa);
    RSA_free(ekRsa);
    
    result = tpm_free_context(hContext,hTPMPolicy);

    if (result != TSS_SUCCESS ) {
        syslog(LOG_ERR, "Error in aik context for free %s and %d ",
                __FILE__,__LINE__);
        return result;
    }
    
    return 0;
}

int get_ekcert()
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_HNVSTORE hNV;
    TSS_HPOLICY	hNVPolicy;
    TSS_HPOLICY	hTPMPolicy;
    UINT32 blobLen;
    UINT32 nvIndex = TSS_NV_DEFINED|TPM_NV_INDEX_EKCert;
    UINT32 offset;
    UINT32 ekOffset;
    UINT32 certBufLen;
    BYTE *certBuf;
    BYTE *blob;
    UINT32 tag, certType;
    int result;
    
    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        return result;
    }

    result = tpm_create_context(&hContext, &hTPM, &hSRK,
            &hTPMPolicy, &hNVPolicy);

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error in aik context for generating ek");
        return result;
    }

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNV);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_CreateObject(TSS_OBJECT_TYPE_NV) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }
    result = Tspi_SetAttribUint32(hNV, TSS_TSPATTRIB_NV_INDEX, 0, nvIndex);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_SetAttribUint32 failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }


    /* Try reading certificate header from NV memory */

    result = Tspi_Policy_AssignToObject(hNVPolicy, hNV);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_AssignToObject failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }

    blobLen = 5;
  
    /* Follwing is the TGC spec for the TPM certifice in the NV RAM
     *
    typedef struct tdTCG_PCCLIENT_STORED_CERT {
    TCG_PCCLIENT_STRUCTURE_TAG tag; // first 2 bytes is tag
    BYTE certTyp // 1 Byte
    UINT16 certSize; // 2 Byte
    BYTE[] cert;
    } TCG_PCCLIENT_STORED_CERT ;
    Minimum total 5 bytes
    */
    
#define CERT_START_OFFSET 5  // see above cert header
    
    result = Tspi_NV_ReadValue(hNV, 0, &blobLen, &blob);

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_NV_ReadValue failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        syslog(LOG_ERR, "Unable to read EK Certificate from TPM\n");
        return result;
    }
    
    if (blobLen < CERT_START_OFFSET)
        goto parseerr;
    
    tag =  GET_SHORT_UINT16(blob,0);  //// certificate tag in first two byte
    
    if (tag != TCG_TAG_PCCLIENT_STORED_CERT)
        goto parseerr;
    
    certType = blob[2]; // certtype at byte 2 --see header
    
    if (certType != TCG_FULL_CERT)
        goto parseerr;
    
    certBufLen = GET_SHORT_UINT16(blob,3);  // total size of the certificate at offset 3

    offset = CERT_START_OFFSET;

    result = Tspi_NV_ReadValue(hNV, offset, &blobLen, &blob); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_NV_ReadValue failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        return result;
    }
   
    /* following is the certificate structure
    
    typedef struct tdTCG_FULL_CERT {
    TCG_PCCLIENT_STRUCTURE_TAG tag; // 2 bytes 
    BYTE[] cert // entire certificate
    } TCG_FULL_CERT;

    */
    
    if (blobLen < sizeof(UINT16))
        goto parseerr;
    
    tag = GET_SHORT_UINT16(blob,0); // type at offset 0

    if (tag == TCG_TAG_PCCLIENT_FULL_CERT) {
        offset += sizeof(UINT16);
        certBufLen -= sizeof(UINT16);
    } else 	{ /* Marker of cert structure */
            syslog(LOG_ERR, "TPM does not contain FULL CERT ");
            goto parseerr;
    }

    /* Read cert from chip in pieces - too large requests may fail */
    certBuf = malloc(certBufLen);

    if (!certBuf) {
        syslog(LOG_ERR, "Malloc failed in %s and %d ",__FILE__,__LINE__);
        return 1;
    }

    ekOffset = 0;
    while (ekOffset < certBufLen) {
        blobLen = certBufLen - ekOffset;
        if (blobLen > BSIZE)
            blobLen = BSIZE;
        result = Tspi_NV_ReadValue(hNV, offset, &blobLen, &blob); 
        if (result != TSS_SUCCESS) {
            syslog(LOG_ERR, "Tspi_NV_ReadValue failed with 0x%X %s", 
                    result, Trspi_Error_String(result));
            goto read_error;
        }

        memcpy (certBuf+ekOffset, blob, blobLen);
        /*		result = Tspi_Context_FreeMemory (hContext, blob); CKERR; */
        offset += blobLen;
        ekOffset += blobLen;
    }


    if ((result = print_base64(certBuf,certBufLen)) != 0) {
        syslog(LOG_ERR, "Error in converting B64 %s and %d ",__FILE__,__LINE__);
        goto read_error;
    }
    
    result = tpm_free_context(hContext,hTPMPolicy);

    if (result != TSS_SUCCESS ) {
        syslog(LOG_ERR, "Error in aik context for free %s and %d ",
                __FILE__,__LINE__);
        goto read_error;
    }

    free(certBuf);
    return 0;

read_error:
    free(certBuf);
    return result;
parseerr:
    syslog(LOG_ERR, "Failure, unable to parse certificate store structure\n");
    return 2;
}
