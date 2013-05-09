 /*      Publish AIK public key in PEM format and TCPA blob format
 */

#include "xentpm.h"
#include <unistd.h>
#include <limits.h>

/* Get Xen public Key from host certificate
 * */
static int
get_xen_rsa_modulus(char* b64_xen_cert, BYTE* CA_Key, unsigned int size)
{
    BIO *bufio;
    RSA *rsa;
    X509 *x509;
    int modulus_len;
    BYTE* modulus_buffer;
    int key_len ;
    BYTE* key_buffer = NULL; ;
    int result = XENTPM_E_INTERNAL; 
    EVP_PKEY * pub_key = NULL;  

    if (!b64_xen_cert) {
        syslog(LOG_ERR, "XenServer Certificate not passed \n");
        goto out;
    }

    key_buffer = base64_decode(b64_xen_cert, &key_len);

    if (!key_buffer) {
        syslog(LOG_ERR, "Unable to decode XenServer cert  %s\n", b64_xen_cert);
        goto out;
    }

    bufio = BIO_new_mem_buf((void*)key_buffer, key_len);

    if ((bufio == NULL) || 
            ((x509 = PEM_read_bio_X509(bufio, NULL, NULL, NULL)) == NULL)) {
        syslog(LOG_ERR , "Unable to read cert in PEM_read_bio_X509 %s\n", b64_xen_cert);
        goto free_key;
    }

    if ((pub_key = X509_get_pubkey(x509)) == NULL) {
        syslog(LOG_ERR , "Unable to get pub_key from cert  %s\n", b64_xen_cert);
        goto free_key;
    }

    rsa = NULL;
    switch (pub_key->type) {
        case EVP_PKEY_RSA:
            rsa = pub_key->pkey.rsa;
            break;
        default:
            syslog(LOG_ERR , "Xen Pub key not RSA %s\n", b64_xen_cert);
            goto free_key;
    }

    if(!rsa){
        syslog(LOG_ERR , "Unable to read pub key from Xen Cert  \
                %s\n",b64_xen_cert);
        goto free_x509;
    }

    //TODO log size as well
    modulus_len = BN_num_bytes(rsa->n);
    modulus_buffer = (BYTE*)malloc(modulus_len);
    if (!modulus_buffer) {
        syslog(LOG_ERR, "Unable to allocate memory %s and %d \n",
                __FILE__, __LINE__);
        goto free_x509; 
    }
    /* TODO:// Fill in the exact size 
     **/
    modulus_len = BN_bn2bin(rsa->n, modulus_buffer);
    if (modulus_len < size) {
        syslog(LOG_INFO, "Partial PCA Key, Xen Key size is %x,\n", modulus_len);
        syslog(LOG_INFO, "Xen Cert %s\n", b64_xen_cert);
        memcpy(CA_Key, modulus_buffer, modulus_len);
        memset(CA_Key+ modulus_len, 0xff, size - modulus_len); // check diff with ff vs 00
    }
    else if (modulus_len > size) {
        syslog(LOG_INFO, "Partial Xen Key for CA, Xen key size is %x,\n", modulus_len);
        syslog(LOG_INFO, "Xen Cert %s\n", b64_xen_cert);
        memcpy(CA_Key, modulus_buffer, size);
    }
    else {
        memcpy(CA_Key, modulus_buffer, size);
    }    

    result = XENTPM_SUCCESS;
    free(modulus_buffer);

free_x509:
    X509_free(x509);
free_key:    
    free(key_buffer);
out:
    return result;
}


int generate_aik(char* b64_xen_cert) 
{
    TSS_HCONTEXT context;
    TSS_HTPM tpm_handle;
    TSS_HKEY srk_handle;
    TSS_HKEY aik_handle;
    TSS_HKEY pca_handle;
    TSS_HPOLICY	tpm_policy;
    TSS_HPOLICY	srk_policy;
    BYTE CA_Key[TSS_DAA_LENGTH_N]; // 2048 bits or 256 Bytes 
    BYTE* tcpablob;
    UINT32 tcpablob_len;
    BYTE*  attrblob;
    UINT32 attrblob_len;
    TSS_UUID aik_uuid = CITRIX_UUID_AIK; 
    int result;

    syslog(LOG_ERR, "xentpm --generate_aik enter");
    
    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
            
    }
    
    result = tpm_create_context(&context, &tpm_handle, &srk_handle, 
                &tpm_policy, &srk_policy); 

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error in aik context for generating aik");
        goto out;
    }
    
    result = Tspi_Context_GetKeyByUUID(context, TSS_PS_TYPE_SYSTEM,
                aik_uuid, &aik_handle);
    
    if (result == TSS_SUCCESS) {
        /* Key found */               
        syslog(LOG_INFO, "Tspi_Context_GetKeyByUUID found Key,\ 
            Not generating New AIK "); 
        goto free_context;        
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
        goto free_context;
    }

    if ((result = get_xen_rsa_modulus(b64_xen_cert, CA_Key, 
            sizeof(CA_Key))) != 0) {
        result = XENTPM_E_CERT;  
        goto free_context;
    }
    
    result = Tspi_SetAttribData(pca_handle, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, sizeof(CA_Key), CA_Key); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_SetAttribData(PCA, RSAKEY_INFO) failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        goto free_context;
    }


    /* Create AIK object */
    result = Tspi_Context_CreateObject(context,
            TSS_OBJECT_TYPE_RSAKEY, 
            TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048, 
            &aik_handle);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_CreateObject(RSAKEY, TSS_KEY_TYPE_IDENTITY) \
                failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        goto free_context;
    }


    /* Generate new AIK  */
    result = Tspi_TPM_CollateIdentityRequest(tpm_handle, srk_handle, pca_handle, 
            strlen("citrix"), "citrix", aik_handle, TSS_ALG_AES, &tcpablob_len, 
            &tcpablob);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_CollateIdentityRequest failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        goto free_context;
    }

    /* Output file with AIK blob for TPM future Use 
     * The output of this call is TPM_KEY(12) struct
     * Used for loading an AIK in TPM
    */
    result = Tspi_GetAttribData(aik_handle, TSS_TSPATTRIB_KEY_BLOB,
            TSS_TSPATTRIB_KEYBLOB_BLOB, &attrblob_len, &attrblob); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        goto free_context;
    }

    result = register_aik_uuid(context, aik_handle);
    syslog(LOG_ERR, "xentpm --generate_aik exit ");
free_context:  
    tpm_free_context(context, tpm_policy);
out:
    return result;
}



/*
 * outputs the AIK PEM base 64 key to stdout
 *
 * Return values:
 * 0x00000000 - success
 */
int get_aik_pem() 
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

    if ((result = take_ownership()) != 0) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        goto out;
    }
    
    result = tpm_create_context(&context, &tpm_handle, &srk_handle, 
                &tpm_policy, &srk_policy); 
    if(result != TSS_SUCCESS ) {
        syslog(LOG_ERR, "Error in aik context for generating aik_pem");
        goto out;
    }
    
    if ( (result = load_aik_tpm(context,  srk_handle, 
            &aik_handle)) != TSS_SUCCESS) {
        syslog(LOG_ERR,  "get_aik_pem Unable to Load aik");
        result = XENTPM_E_INTERNAL;
        goto free_context;
    }

    /* Aik pub key read from the blob */
    result = Tspi_GetAttribData(aik_handle, TSS_TSPATTRIB_RSAKEY_INFO,
                TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &aikblob_len, &aikblob); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(AIK, RSA_MODULUS) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        goto free_context;
    }

    result = Tspi_GetAttribData(aik_handle, TSS_TSPATTRIB_RSAKEY_INFO,
                TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &exponent_size, &exponent); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(AIK, RSA_EXPONENT) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        goto free_context;
    }

    aikPubKey = RSA_new();
    aikPubKey->n = BN_bin2bn(aikblob, aikblob_len, NULL);
    aikPubKey->e = BN_bin2bn(exponent, exponent_size, NULL);
    PEM_write_RSA_PUBKEY(stdout, aikPubKey);
    RSA_free(aikPubKey);

free_context:
    tpm_free_context(context,tpm_policy);
out:    
    return result;
}

/*
* outputs the AIK TCPA base 64 key to stdout
*
* Return values:
* 0x00000000 - success
* 0x00000003 - Bad parameter - usually means AIK blob is not valid
*/
int get_aik_tcpa() 
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

    if ((result = take_ownership()) != 0) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        goto out;
    }

    result = tpm_create_context(&context, &tpm_handle, &srk_handle, 
            &tpm_policy, &srk_policy); 

    if(result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error in aik context for generating aik tcpa");
        goto out;
    }

    if ( (result = load_aik_tpm( context, srk_handle, 
                    &aik_handle)) != 0) {
        syslog(LOG_ERR,  "get_aik_tcpa Unable to Load aik");
        result = XENTPM_E_INTERNAL;
        goto free_context;
    }

    result = Tspi_GetAttribData(aik_handle, TSS_TSPATTRIB_KEY_BLOB,
            TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &tcpa_keyblob_len, &tcpa_keyblob); 
    
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetAttribData(AIK, PUBLIC_KEY) failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        goto free_context;
    }
    if ((result = print_base64(tcpa_keyblob, tcpa_keyblob_len)) != 0) {
        syslog(LOG_ERR, "Error in converting B64 %s and %d ",__FILE__,__LINE__);
    }

free_context:
    tpm_free_context(context,tpm_policy);
out:    
    return result;
}

