/*
 * xenquote.c
 *
 * Produce a PCR quote using an AIK.
 *
 * All available PCR's are masked
 * Nonce is fixed at 0 for now.
 *
 * The format of the quote file output is as follows:
 * 2 bytes of PCR bitmask length (big-endian)
 * PCR bitmask (LSB of 1st byte is PCR0, MSB is PCR7; LSB of 2nd byte is PCR8, etc)
 * 4 bytes of PCR value length (20 times number of PCRs) (big-endian)
 * PCR values
 * 256 bytes of Quote signature
 *
 * Note that the 1st portion is the serialized TPM_PCR_SELECTION that gets hashed.
 *
 * Takes an optional challenge file to be hashed as the externalData input
 * to the Quote. This would typically be supplied by the challenger to prevent
 * replay of old Quote output. If no file is specified the challenge is zeros.
 */

#include "xentpm.h" 
#include <arpa/inet.h>

#define PCR_QUOTE_LEN (TCPA_SHA1_160_HASH_LEN)
#define BITS_PER_BYTE CHAR_BIT
#define SET_BIT(buf, i)  ((((BYTE*)buf)[i/BITS_PER_BYTE] |= 1 << (i%BITS_PER_BYTE)))
#define ROUNDUP_BYTE(x)  ((x + BITS_PER_BYTE - 1 ) / BITS_PER_BYTE)

/* return nonce sha1 from user provided nonce 
*/
static int 
get_nonce_sha1(char* b64_nonce, BYTE * nonce_hash, TSS_HCONTEXT tpm_context)
{
    int nonce_len ;
    BYTE* nonce_buf = NULL;
    
    nonce_buf = base64_decode(b64_nonce, &nonce_len);
    if (!nonce_buf) {
        syslog(LOG_ERR, "Unable to b64 decode nonce \n");
        return TSS_E_BAD_PARAMETER; //BAD_PARAM
    }

    // Hash the nonce
    sha1(tpm_context, nonce_buf, nonce_len, nonce_hash);
    free(nonce_buf);
    return TSS_SUCCESS;
}

/*
 * tpm_quote return following values in serealized binary blob
 *
 *   1)uit16 PCRSelectMAskSize 
 *   2)BYTE* PCRSelectMast
 *   3)uint32 QuoteSize 
 *   4)BYTE *Quote (PCR Quote readable in Text)
 *   5)BYTE *Signature ( RSA Sign the Quote_Info STructre from AIK Pub)
 *
 * The TPM/Trousers generate The composite hash of fields 1- 4
 * this is used to fill TPM_Quote strcutre for verifying quote.
 * the Signature is of TPM_Quote from the TPM 
*/

int
tpm_quote(char * b64_nonce)
{
    TSS_HCONTEXT tpm_context;
    TSS_HTPM tpm_handle;
    TSS_HKEY srk_handle;
    TSS_HKEY aik_handle;
    TSS_HPOLICY	srk_policy;
    TSS_HPOLICY	tpm_policy;
    TSS_HPCRS pcr_handle;
    TSS_VALIDATION valid; //quote validation structure
    UINT32 pcr_property;
    UINT32 max_pcr;
    BYTE*  pcr_mask ;
    UINT32 mask_size;
    BYTE*  quote_buf;
    UINT32 quote_buf_len;
    BYTE*  marker;
    BYTE*  api_buf;
    UINT32 api_buf_len;
    BYTE   nonce_hash[SHA_DIGEST_LENGTH];
    int	   i;
    int	   result;
    int alloc_size;

    syslog(LOG_ERR, "Request for TPM quote generation for nonce %s \n", b64_nonce);

    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "tpm_quote Error 0x%X taking ownership of TPM.\n", result);
        goto out;
    }
    
    if ((result = tpm_create_context(&tpm_context, &tpm_handle, &srk_handle, 
                &tpm_policy, &srk_policy)) != TSS_SUCCESS) { 
        syslog(LOG_ERR, "Error in aik context for generating aik_pem");
        goto out;
    }

    if ((result = get_nonce_sha1(b64_nonce, nonce_hash, 
                tpm_context)) != TSS_SUCCESS) {
        syslog(LOG_ERR, "Unable to b64 decode nonce \n");
        goto free_context;
    }  

    if ((result = load_aik_tpm(tpm_context, 
                srk_handle, &aik_handle)) != TSS_SUCCESS) {
        syslog(LOG_ERR, "xenquote Unable to load citrix aik");
        goto free_context;
    }


    /* Create PCR list to be quoted 
     * We will quote all the PCR's
     */
    pcr_property = TSS_TPMCAP_PROP_PCR;
    
    if ((result = Tspi_TPM_GetCapability(tpm_handle, TSS_TPMCAP_PROPERTY,
	        	sizeof(pcr_property), (BYTE *)&pcr_property, &api_buf_len, 
                &api_buf)) != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_TPM_GetCapability failed with 0x%X %s", result, 
            Trspi_Error_String(result));
        goto free_context;
    }

    max_pcr = *(UINT32 *)api_buf;
    Tspi_Context_FreeMemory(tpm_context, api_buf);
    mask_size = ROUNDUP_BYTE(max_pcr); // no of bytes for PCR MASK
    
    if ((result = Tspi_Context_CreateObject(tpm_context, TSS_OBJECT_TYPE_PCRS,
	        	TSS_PCRS_STRUCT_INFO, &pcr_handle)) != TSS_SUCCESS) { 
        syslog(LOG_ERR, "Tspi_Context_CreateObject(PCR) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        goto free_context;
    }

	
    /* Allocate buffer for SelectMASK + Quotedata
     * Also select all the availble PCRS
     *  //return to caller following buffer
     *   1)uit16 PCRSelectMAskSize //2 byets
     *   2)BYTE* PCRSelectMask    // which pcrs selected (all)
     *   3)uint32 QuoteSize       //  Quotes 
     *   4)BYTE *Quote (PCR Quote readable in Text)
     */
    alloc_size = sizeof(UINT16) + mask_size + sizeof(UINT32) + 
                    PCR_QUOTE_LEN * max_pcr;
    quote_buf = (BYTE*)malloc(alloc_size); 
    
    if (!quote_buf) {
        syslog(LOG_ERR, "Unable to allocate memory %d , %s and %d \n",
        alloc_size, __FILE__, __LINE__);
        result = XENTPM_E_INTERNAL;
        goto free_quote;
    }
    
    *(UINT16 *)quote_buf = htons(mask_size); // set num of PCRS
     
    pcr_mask = quote_buf + sizeof(UINT16); // mask init
    memset(pcr_mask, 0, mask_size); 

    for (i = 0;i < max_pcr; i++) {
        result = Tspi_PcrComposite_SelectPcrIndex(pcr_handle, i); 
        
        if (result != TSS_SUCCESS) {
            syslog(LOG_ERR, "Tspi_PcrComposite_SelectPcrIndex failed with 0x%X %s", 
                 result, Trspi_Error_String(result));
            goto free_quote;
        }
        SET_BIT(pcr_mask, i);
    }

    /* Create TSS_VALIDATION struct for Quote
     typedef struct tdTSS_VALIDATION
    { 
        TSS_VERSION  versionInfo;
        UINT32       ulExternalDataLength; //nonce len
        BYTE*        rgbExternalData; // nonce data
        UINT32       ulDataLength; //sizeof quote_info
         BYTE*     rgbData; //tpm_quote_info
        UINT32    ulValidationDataLength;
        BYTE*     rgbValidationData; // signature of the quote_info_structure
    } TSS_VALIDATION;
    */

    /* TPM_QUOTE_INFO structure IDL Definition
        typedef struct tdTPM_QUOTE_INFO {
            TPM_STRUCT_VER version;
            BYTE fixed[4];
            TPM_COMPOSITE_HASH digestValue; // sha1 of pcr_maskSize,pcr_mask,quotelen,quoteData
            TPM_NONCE externalData,
        }   TPM_QUOTE_INFO;
  
        Following  details from TPM SPEC 1.2
        
        TPM_STRUCT_VER version This MUST be 1.1.0.0
        BYTE fixed This SHALL always be the string ‘QUOT’
        TPM_COMPOSITE_HASH digestValue This SHALL be the result of i
        the composite hash algorithm using the current values of the 
        requested PCR indices.  
        TPM_NONCE externalData 160 bits of externally supplied data
    */
                                                                                         
    valid.ulExternalDataLength = sizeof(nonce_hash);
    valid.rgbExternalData = nonce_hash;

    /* Perform Quote */
    result = Tspi_TPM_Quote(tpm_handle, aik_handle, pcr_handle, &valid);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_TPM_Quote failed with 0x%X %s",
            result, Trspi_Error_String(result));
        goto free_quote;
    }


    /* Fill in the PCR buffer */

    marker = quote_buf + sizeof(UINT16) + mask_size; // no of PCRs
    *(UINT32 *)marker = htonl (PCR_QUOTE_LEN*max_pcr); //set the quote size
    marker += sizeof(UINT32);
    for (i = 0;i < max_pcr; i++) {
        result = Tspi_PcrComposite_GetPcrValue(pcr_handle, i, &api_buf_len,
                &api_buf);
        if (result != TSS_SUCCESS) {
            syslog(LOG_ERR, "Tspi_PcrComposite_GetPcrValue failed with 0x%X %s", 
                    result, Trspi_Error_String(result));
            goto free_quote;
        }
        memcpy (marker, api_buf, api_buf_len); // individual PCR quote
        marker += api_buf_len;
    }

    
    /*  appned on the rgbValidationData (quote info singature)
     *  onto the end of the quote buffer
     */
    quote_buf_len = marker - quote_buf;
    alloc_size = quote_buf, quote_buf_len + valid.ulValidationDataLength;
    quote_buf = realloc(quote_buf, alloc_size);

    if (!quote_buf) {
        syslog(LOG_ERR, "Unable to realloc memory for size %d at %s and %d \n",
            alloc_size, __FILE__, __LINE__);
        result = XENTPM_E_INTERNAL; 
        goto free_context;
    }

    memcpy(&quote_buf[quote_buf_len], valid.rgbValidationData,
            valid.ulValidationDataLength);
    quote_buf_len += valid.ulValidationDataLength;

    if ((result = print_base64(quote_buf,quote_buf_len)) != 0) {
        syslog(LOG_ERR, "Error in converting B64 %s and %d ", __FILE__, __LINE__);
        result = XENTPM_E_INTERNAL; 
        goto free_quote;
        
    }

    syslog(LOG_INFO, "Generate TPM Quote Success!\n");

free_quote:
    free(quote_buf);
free_context:
    Tspi_Context_CloseObject(tpm_context, srk_policy);
    tpm_free_context(tpm_context, tpm_policy);
out:    
    return result;
}

