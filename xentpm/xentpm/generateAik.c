 /*      Publish AIK public key in PEM format and TCPA blob format
 */

#include "xentpm.h"
#include <unistd.h>
#include <limits.h>

/* Get Xen public Key from host certificate
 * */
static void
get_xen_rsa_modulus(char* b64_xen_cert, BYTE* CA_Key, unsigned int size)
{
    BIO *bufio;
    RSA *rsa;
    X509 *x509;
    int modulus_len;
    BYTE* modulus_buffer;
    int key_len ;
    BYTE* key_buffer = NULL; ;
    memset (CA_Key, 0xff, size);
    
    if (!b64_xen_cert)
        goto set_const;

    key_buffer = base64_decode(b64_xen_cert, &key_len);

    if (!key_buffer) {
        goto set_const;
    }

    bufio = BIO_new_mem_buf((void*)key_buffer, key_len);

    if ((x509 = PEM_read_bio_X509(bufio, NULL, NULL, NULL)) == NULL) {
        goto free_key;
    }

    rsa = X509_get_pubkey(x509)->pkey.rsa;

    if(!rsa){
        goto free_x509;
    }
    modulus_len = BN_num_bytes(rsa->n);

    modulus_buffer = (BYTE*)malloc(modulus_len);

    if (!modulus_buffer) {
        syslog(LOG_ERR, "Unable to allocate memory %s and %d \n",
                __FILE__, __LINE__);
        goto free_x509; 
    }

    modulus_len = BN_bn2bin(rsa->n, modulus_buffer);
    
    //TODO log in case of mismatch of size
    // Increase the Logs for all API start and end
    if (modulus_len < size) {
        memcpy(CA_Key, modulus_buffer, modulus_len);
        memset(CA_Key+ modulus_len, 0xff, size - modulus_len);
        goto free_modulus; 
    }
    else
        memcpy(CA_Key, modulus_buffer, size);

free_modulus:
    free(modulus_buffer);
free_x509:
    X509_free(x509);
free_key:    
    free(key_buffer);
set_const:
    return;
}


// TODO context cleanup for all errors
//
int generate_aik(char *aik_blob_path, char* b64_xen_cert) 
{
    TSS_HCONTEXT context;
    TSS_HTPM tpm_handle;
    TSS_HKEY srk_handle;
    TSS_HKEY aik_handle;
    TSS_HKEY pca_handle;
    TSS_HPOLICY	tpm_policy;
    TSS_HPOLICY	srk_policy;
    BYTE CA_Key[TSS_DAA_LENGTH_N]; // 2048 bits or 256 Bytes 
    FILE *f_out;
    BYTE* tcpablob;
    UINT32 tcpablob_len;
    BYTE*  attrblob;
    UINT32 attrblob_len;
    int  result;

    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        return result;
    }
   // TODO : fail if blob is present with a specific err code
   //     error on     : blob already present 
    if ((result = access(aik_blob_path, R_OK)) == 0) {
        syslog(LOG_INFO, "Aikblob already present when taking ownership \
            %s \n", aik_blob_path);
    }
   
   // TODO : partial cotext clearing
    result = tpm_create_context(&context, &tpm_handle, &srk_handle, 
                &tpm_policy, &srk_policy); 

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error in aik context for generating aik");
        return result;
    }

    /* Privacy CA key 
     * use XenServer Public Key 
     */
    result = Tspi_Context_CreateObject(context,
                TSS_OBJECT_TYPE_RSAKEY,
                TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048,
                &pca_handle);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CreateObject(RSAKEY, TSS_KEY_TYPE_LEGACY) \
            failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }

    get_xen_rsa_modulus(b64_xen_cert, CA_Key, sizeof(CA_Key));
    
    result = Tspi_SetAttribData(pca_handle, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, sizeof(CA_Key), CA_Key); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_SetAttribData(PCA, RSAKEY_INFO) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }


    /* Create AIK object */
    result = Tspi_Context_CreateObject(context,
            TSS_OBJECT_TYPE_RSAKEY,
            TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048, &aik_handle);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_CreateObject(RSAKEY, TSS_KEY_TYPE_IDENTITY) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }


    /* Generate new AIK  */
    //TODO set label to citrix and set len
   result = Tspi_TPM_CollateIdentityRequest(tpm_handle, srk_handle, pca_handle, 0, "",
            aik_handle, TSS_ALG_AES, &tcpablob_len, &tcpablob);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_CollateIdentityRequest failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }

    Tspi_Context_FreeMemory(context, tcpablob);

    /* Output file with AIK blob for TPM future Use 
     * The output of this call is TPM_KEY(12) struct
     * Used for loading an AIK in TPM
    */
    result = Tspi_GetAttribData(aik_handle, TSS_TSPATTRIB_KEY_BLOB,
            TSS_TSPATTRIB_KEYBLOB_BLOB, &attrblob_len, &attrblob); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(KEY_BLOB) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }


    if ((f_out = fopen (aik_blob_path, "wb")) == NULL) {
        syslog(LOG_ERR, "Unable to open %s for output\n", aik_blob_path);
        return 1;
    }
    if (fwrite (attrblob, 1, attrblob_len, f_out) != attrblob_len) {
        syslog(LOG_ERR, "Unable to write to %s\n", aik_blob_path);
        return 1;
    }
    fclose (f_out);

    /*free all memory with this context 
     * close context object
     */
    result = Tspi_Context_CloseObject(context, aik_handle);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CloseObject failed  0x%X %s", 
            result, Trspi_Error_String(result));
       // return result;
    }
    result = Tspi_Context_CloseObject(context, pca_handle);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CloseObject failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        //return result;
    }
    
    tpm_free_context(context, tpm_policy);
    return 0;
}



/*
 * outputs the AIK PEM base 64 key to stdout
 *
 * Return values:
 * 0x00000000 - success
 * 0x00000003 - Bad parameter - usually means AIK blob is not valid
 */
int get_aik_pem(char *aik_blob_path) 
{
    TSS_HCONTEXT context;
    TSS_HTPM tpm_handle;
    TSS_HKEY srk_handle;
    TSS_HKEY aik_handle;
    TSS_HPOLICY	tpm_policy;
    TSS_HPOLICY	srk_policy;
    BYTE *aikblob;
    UINT32 aikblob_len;
    RSA	*aikPubKey;
    UINT32 exponent_size;
    BYTE *exponent;
    int  result;

    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        return result;
    }

    result = tpm_create_context(&context, &tpm_handle, &srk_handle, 
                &tpm_policy, &srk_policy); 

    if(result != TSS_SUCCESS ) {
        syslog(LOG_ERR, "Error in aik context for generating aik_pem");
        return result;
    }
    // TODO : corrut or missing
    //
    if ( (result = load_aik_tpm(aik_blob_path, context,  srk_handle, &aik_handle)) != 0) {
        syslog(LOG_ERR, "Unable to read aik blob %s\n", aik_blob_path);
        return result;
    }

    // Aik pub key read from the blob 
    result = Tspi_GetAttribData(aik_handle, TSS_TSPATTRIB_RSAKEY_INFO,
                TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &aikblob_len, &aikblob); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(AIK, RSA_MODULUS) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_GetAttribData(aik_handle, TSS_TSPATTRIB_RSAKEY_INFO,
                TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &exponent_size, &exponent); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(AIK, RSA_EXPONENT) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }

    aikPubKey = RSA_new();
    aikPubKey->n = BN_bin2bn(aikblob, aikblob_len, NULL);
    aikPubKey->e = BN_bin2bn(exponent, exponent_size, NULL);
    PEM_write_RSA_PUBKEY(stdout, aikPubKey);
    RSA_free(aikPubKey);

    tpm_free_context(context,tpm_policy);
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
    TSS_HCONTEXT context;
    TSS_HTPM tpm_handle;
    TSS_HKEY srk_handle;
    TSS_HKEY aik_handle;
    TSS_HPOLICY	tpm_policy;
    TSS_HPOLICY	srk_policy;
    BYTE *tcpa_keyblob;
    UINT32 tcpa_keyblob_len;
    int  result;
    
    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        return result;
    }
    result = tpm_create_context(&context, &tpm_handle, &srk_handle, 
            &tpm_policy, &srk_policy); 

    if(result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error in aik context for generating aik tcpa");
        return result;
    }

    if ( (result = load_aik_tpm(aik_blob_path, context, 
            srk_handle, &aik_handle)) != 0) {
        syslog(LOG_ERR, "Unable to readn file %s\n", aik_blob_path);
        return result;
    }
   
    result = Tspi_GetAttribData(aik_handle, TSS_TSPATTRIB_KEY_BLOB,
            TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &tcpa_keyblob_len, &tcpa_keyblob); 
    
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(AIK, PUBLIC_KEY) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }

    if ((result = print_base64(tcpa_keyblob, tcpa_keyblob_len)) != 0) {
        syslog(LOG_ERR, "Error in converting B64 %s and %d ",__FILE__,__LINE__);
        return 1;
    }
    
    tpm_free_context(context, tpm_policy);
    return 0;
}

