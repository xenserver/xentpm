/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */
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

/* Get endorsement key (PEM) from TPM */
int get_endorsment_key()
{
    TSS_HCONTEXT context;
    TSS_HPOLICY	tpm_policy;
    TSS_HPOLICY	srk_policy;
    TSS_HTPM tpm_handle;
    TSS_HKEY srk_handle;
    TSS_RESULT result;
    TSS_HKEY pub_ek;
    UINT32 modulusLen;
    UINT32 exponentLen;
    BYTE *modulus;
    BYTE *exponent;
    RSA *ek_rsa;
    
    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        goto out;
    }
    
    result = tpm_create_context(&context, &tpm_handle, &srk_handle, 
            &tpm_policy, &srk_policy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error in aik context for generating ek");
        goto out;
    }
    result = Tspi_TPM_GetPubEndorsementKey (tpm_handle, TRUE, NULL, &pub_ek);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error Reading TPM EK 0x%x (%s) \n", 
            result, Trspi_Error_String(result));
        syslog(LOG_ERR, "Error Reading TPM EK, check the owner password after \
            enabling the TPM \n");
        goto free_context;
    }

    result = Tspi_GetAttribData (pub_ek, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &modulusLen, &modulus);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error getting TPM EK RSA modulus attribute %s \n", 
            Trspi_Error_String(result));
        goto close_obj;
    }
    if (modulusLen != TSS_DAA_LENGTH_N) {
        syslog(LOG_ERR, "Ek key modules len not equal TSS_DAA_LENGTH_N  %u \n",
            modulusLen);
        result = XENTPM_E_INTERNAL;
        goto close_obj;
    }

    result = Tspi_GetAttribData(pub_ek, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &exponentLen, &exponent);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%x on Tspi_Context_GetAttr Exponent\n", result);
        goto close_obj;
    }
    
    ek_rsa = RSA_new();
    ek_rsa->n = BN_bin2bn (modulus, modulusLen, NULL);
    ek_rsa->e = BN_bin2bn(exponent, exponentLen, NULL);
    PEM_write_RSA_PUBKEY(stdout, ek_rsa);
    RSA_free(ek_rsa);

close_obj:
    Tspi_Context_CloseObject (context, pub_ek);
free_context: 
    Tspi_Context_CloseObject(context, srk_policy);
    tpm_free_context(context,tpm_policy);
out:
    return result;
}

/* Get Endoresement Key certificate  
 * */

int get_endorsment_keycert()
{
    TSS_HCONTEXT context;
    TSS_HTPM tpm_handle;
    TSS_HKEY srk_handle;
    TSS_HNVSTORE nv_handle;
    TSS_HPOLICY	nv_policy;
    TSS_HPOLICY	tpm_policy;
    UINT32 blob_len;
    UINT32 nv_index;
    UINT32 offset;
    UINT32 ek_offset;
    UINT32 certbuf_len;
    BYTE *certbuf;
    BYTE *blob;
    UINT32 tag, cert_type;
    int result;
    
    result = take_ownership();
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        goto out;
    }

    result = tpm_create_context(&context, &tpm_handle, &srk_handle,
            &tpm_policy, &nv_policy);

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error in aik context for generating ek");  
        goto out;
    }

    result = Tspi_Context_CreateObject(context, TSS_OBJECT_TYPE_NV, 0, &nv_handle);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_CreateObject(TSS_OBJECT_TYPE_NV) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        goto free_context;
    }
    
    nv_index = TSS_NV_DEFINED|TPM_NV_INDEX_EKCert;
    result = Tspi_SetAttribUint32(nv_handle, TSS_TSPATTRIB_NV_INDEX, 0, 
                 nv_index);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_SetAttribUint32 failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        goto free_context;
    }
    /* Try reading certificate header from NV memory */
    result = Tspi_Policy_AssignToObject(nv_policy, nv_handle);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_AssignToObject failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        goto free_context;
    }
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
#define CERT_START_OFFSET 5  /* see above cert header */
    
    blob_len = CERT_START_OFFSET;
    result = Tspi_NV_ReadValue(nv_handle, 0, &blob_len, &blob);

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_NV_ReadValue failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        syslog(LOG_ERR, "Unable to read EK Certificate from TPM\n");
        goto free_context;
    }
    
    if (blob_len < CERT_START_OFFSET) {
        syslog(LOG_ERR, "Failure, cert blob len smaller then cert offset\n");
        result = XENTPM_E_CERT_PARSE; 
        goto free_context;
    }
    
    tag =  GET_SHORT_UINT16(blob,0);  /* certificate tag in first two byte */
    if (tag != TCG_TAG_PCCLIENT_STORED_CERT) {
        syslog(LOG_ERR, "Failure, cert tag not TCG_TAG_PCCLIENT_STORED_CERT\n");
        result = XENTPM_E_CERT_PARSE;
        goto free_context;
    }

    cert_type = blob[2]; /* certtype at byte 2 --see header */
    if (cert_type != TCG_FULL_CERT) {
        syslog(LOG_ERR, "Failure, cert type not TCG_FULL_CERT\n");
        result = XENTPM_E_CERT_PARSE; 
        goto free_context;
    }
    
    /* total size of the certificate at offset = 3;*/
    certbuf_len = GET_SHORT_UINT16(blob,3);  
    offset = CERT_START_OFFSET;
    result = Tspi_NV_ReadValue(nv_handle, offset, &blob_len, &blob); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_NV_ReadValue failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        result = XENTPM_E_CERT_PARSE; 
        goto free_context;
    }
    /* following is the certificate structure
    typedef struct tdTCG_FULL_CERT {
    TCG_PCCLIENT_STRUCTURE_TAG tag; // 2 bytes 
    BYTE[] cert // entire certificate
    } TCG_FULL_CERT;
    */
    if (blob_len < sizeof(UINT16)) {
        syslog(LOG_ERR, "Failure, unable read certificate");
        result = XENTPM_E_CERT_PARSE; 
        goto free_context;
    }
    
    tag = GET_SHORT_UINT16(blob, 0); // type at offset 0
    if (tag == TCG_TAG_PCCLIENT_FULL_CERT) {
        offset += sizeof(UINT16);
        certbuf_len -= sizeof(UINT16);
    } else 	{ /* Marker of cert structure */
            result = XENTPM_E_CERT_PARSE; 
            syslog(LOG_ERR, "TPM does not contain FULL CERT ");
            goto free_context;
    }

    /* Read cert from chip in chunks */
    certbuf = malloc(certbuf_len);
    if (!certbuf) {
        syslog(LOG_ERR, "Malloc failed %d , in %s and %d ", certbuf_len,
            __FILE__,__LINE__);
        result = XENTPM_E_INTERNAL;
    }

    ek_offset = 0;
    while (ek_offset < certbuf_len) {
        blob_len = certbuf_len - ek_offset;
        if (blob_len > BSIZE)
            blob_len = BSIZE;
        
        result = Tspi_NV_ReadValue(nv_handle, offset, &blob_len, &blob); 
        if (result != TSS_SUCCESS) {
            syslog(LOG_ERR, "Tspi_NV_ReadValue failed with 0x%X %s", 
                    result, Trspi_Error_String(result));
            goto read_error;
        }

        memcpy (certbuf+ek_offset, blob, blob_len);
        offset += blob_len;
        ek_offset += blob_len;
    }
    if ((result = print_base64(certbuf, certbuf_len)) != 0) {
        syslog(LOG_ERR, "Error in converting B64 %s and %d ", __FILE__, __LINE__);
    }
    
read_error:
    free(certbuf);
free_context:
    Tspi_Context_CloseObject(context, nv_policy);
    tpm_free_context(context, tpm_policy);
out:
    return result;
}
