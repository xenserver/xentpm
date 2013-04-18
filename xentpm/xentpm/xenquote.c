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
static void sha1(TSS_HCONTEXT hContext, void *shaBuf, UINT32 shaBufLen, BYTE *digest);


int
tpm_quote(char *nonce, char *aik_blob_path)
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_HKEY hAIK;
    TSS_HPOLICY	hSrkPolicy;
    TSS_HPOLICY	hTPMPolicy;
    TSS_HPCRS hPCRs;
    TSS_VALIDATION valid; //quote validation structure
    TPM_QUOTE_INFO *quoteInfo; 
    UINT32 tpmPCRProp;
    UINT32 npcrMax;
    UINT32 npcrBytes;
    UINT32 npcrs = 0;
    BYTE *quoteBuf;
    UINT32 quoteBufLen;
    BYTE *bPointer;
    BYTE *apiBuf;
    UINT32 apiBufLen;
    BYTE nonceHash[20];
    BYTE pcrHash[20];
    BIO *bmem, *b64;
    BYTE* nonceBuf ;
    UINT32 nonceBufLen;
    int	i;
    int	result;

    syslog(LOG_INFO, "Request for TPM Quote Generation!\n");

    result = take_ownership();
    if (result) {
        syslog(LOG_ERR, "Error 0x%X taking ownership of TPM.\n", result);
        return result;
    }
    
    result = tpm_create_context(&hContext, &hTPM, &hSRK, 
            &hTPMPolicy, &hSrkPolicy); 

    if(result != TSS_SUCCESS ) {
        syslog(LOG_ERR, "Error in aik context for generating aik_pem");
        return result;
    }

    // Base64 decode the nonce

    nonceBufLen = strlen(nonce);
    nonceBuf = (BYTE*)malloc(nonceBufLen);
    if (!nonceBuf) {
        syslog(LOG_ERR, "Unable to allocate memory %s and %d \n",__FILE__,__LINE__);
        return 1;
    }
    memset(nonceBuf, 0, nonceBufLen);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(nonce, nonceBufLen);
    bmem = BIO_push(b64, bmem);
    int nonceLen = BIO_read(bmem, nonceBuf, nonceBufLen);
    BIO_free_all(bmem);

    // Hash the nonce
    sha1(hContext, nonceBuf, nonceLen, nonceHash);
    free(nonceBuf);


    if ( (result = load_aik_tpm(aik_blob_path, hContext,  hSRK, &hAIK)) != 0) {
        syslog(LOG_ERR, "Unable to readn file %s\n", aik_blob_path);
        return result;
    }

    
    // Create PCR list to be quoted 
    // We will quote all the PCR's
    tpmPCRProp = TSS_TPMCAP_PROP_PCR;
    result = Tspi_TPM_GetCapability(hTPM, TSS_TPMCAP_PROPERTY,
		sizeof(tpmPCRProp), (BYTE *)&tpmPCRProp, &apiBufLen, &apiBuf); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_TPM_GetCapability failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    npcrMax = *(UINT32 *)apiBuf;
    Tspi_Context_FreeMemory(hContext, apiBuf);
    npcrBytes = (npcrMax + 7) / 8; // PCR MASK
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS,
		TSS_PCRS_STRUCT_INFO, &hPCRs); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CreateObject(PCR) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

	
    // Create TSS_VALIDATION struct for Quote
    /*
    typedef struct tdTSS_VALIDATION
    { 
        TSS_VERSION  versionInfo;
        UINT32       ulExternalDataLength; //nonce len
        BYTE*        rgbExternalData; // nonce data
        UINT32       ulDataLength; //sizeof quote_info
         BYTE*     rgbData; //tpm_quote_info
        UINT32    ulValidationDataLength;
        BYTE*     rgbValidationData;
    } TSS_VALIDATION;
    */


 
    
    valid.ulExternalDataLength = sizeof(nonceHash);
    valid.rgbExternalData = nonceHash;

    // Allocate buffer for SelectMASK + Quotedata
    // Also select all the availble PCRS
    //   1)uit16 PCRSelectMAskSize //2 byets
    //   2)BYTE* PCRSelectMast    // which pcrs selected (all)
    //   3)uint32 QuoteSize       //  Quotes 
    //   4)BYTE *Quote (PCR Quote readable in Text)
    
    quoteBuf = malloc((2 + npcrBytes + 4 + 20 * npcrMax));
    
    if (!quoteBuf) {
        syslog(LOG_ERR, "Unable to allocate memory %s and %d \n",__FILE__,__LINE__);
        return 1;
    }
    
    *(UINT16 *)quoteBuf = htons(npcrBytes);
    
    for (i=0; i<npcrBytes; i++)
        quoteBuf[2+i] = 0;

    for (i=0; i<npcrMax; i++) {
        long pcr = i ;
        result = Tspi_PcrComposite_SelectPcrIndex(hPCRs, pcr); 
        if (result != TSS_SUCCESS) {
            syslog(LOG_ERR, "Tspi_PcrComposite_SelectPcrIndex failed with 0x%X %s", result, Trspi_Error_String(result));
            return result;
        }

        ++npcrs;
        quoteBuf[2+(pcr/8)] |= 1 << (pcr%8);
    }

    // Perform Quote
    result = Tspi_TPM_Quote(hTPM, hAIK, hPCRs, &valid);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_TPM_Quote failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    quoteInfo = (TPM_QUOTE_INFO *)valid.rgbData;

    // Fill in the PCR buffer
    bPointer = quoteBuf + 2 + npcrBytes;
    *(UINT32 *)bPointer = htonl (20*npcrs);
    bPointer += sizeof(UINT32);
    for (i=0; i<=npcrMax; i++) {
        if (quoteBuf[2+(i/8)] & (1 << (i%8))) {
            result = Tspi_PcrComposite_GetPcrValue(hPCRs,i, &apiBufLen,
                     &apiBuf);
            if (result != TSS_SUCCESS) {
                syslog(LOG_ERR, "Tspi_PcrComposite_GetPcrValue failed with 0x%X %s", 
                        result, Trspi_Error_String(result));
                return result;
            }
            memcpy (bPointer, apiBuf, apiBufLen);
            bPointer += apiBufLen;
            Tspi_Context_FreeMemory(hContext, apiBuf);
        }
    }
    quoteBufLen = bPointer - quoteBuf;

    // Test the hash before sending to client
    sha1(hContext, quoteBuf, quoteBufLen, pcrHash);
    if (memcmp(pcrHash, quoteInfo->compositeHash.digest, sizeof(pcrHash)) != 0) {
        // Try with smaller digest length 
        *(UINT16 *)quoteBuf = htons(npcrBytes-1);
        memmove(quoteBuf+2+npcrBytes-1, quoteBuf+2+npcrBytes, quoteBufLen-2-npcrBytes);
        quoteBufLen -= 1;
        sha1(hContext, quoteBuf, quoteBufLen, pcrHash);
        if (memcmp(pcrHash, quoteInfo->compositeHash.digest, sizeof(pcrHash)) != 0) {
            syslog(LOG_ERR, "Inconsistent PCR hash in output of quote\n");
            return 1;
        }
    }

    //
    // Create quote 
    // content of the quote file is following
    // following data is serilized in this order
    //   1)uit16 PCRSelectMAskSize 
    //   2)BYTE* PCRSelectMast
    //   3)uint32 QuoteSize 
    //   4)BYTE *Quote (PCR Quote readable in Text)
    //   5)BYTE *Signature
    //
    // The TPM/Trousers generate The composite hash of fields 1- 4
    // this is used to fill TPM_Quote strcutre for verifying quote
    // the Signature is of TPM_Quote from the TPM 
    // For quote verification read details below.
    //
    
    // Tack on the rgbValidationData onto the end of the quote buffer
    quoteBuf = realloc(quoteBuf, quoteBufLen + valid.ulValidationDataLength);

    if (!quoteBuf) {
        syslog(LOG_ERR, "Unable to allocate memory %s and %d \n",__FILE__,__LINE__);
        return 1;
    }

    memcpy(&quoteBuf[quoteBufLen], valid.rgbValidationData, valid.ulValidationDataLength);
    quoteBufLen += valid.ulValidationDataLength;

    if ((result = print_base64(quoteBuf,quoteBufLen)) != 0) {
        syslog(LOG_ERR, "Error in converting B64 %s and %d ",__FILE__,__LINE__);
        return 1;
    }

    syslog(LOG_INFO, "Generate TPM Quote Success!\n");
    

    result = tpm_free_context(hContext,hTPMPolicy);

    if (result != TSS_SUCCESS ) {
        syslog(LOG_ERR, "Error in aik context for free %s and %d ",__FILE__,__LINE__);
        return result;
    }
    return 0;
}

static void
sha1(TSS_HCONTEXT hContext, void *shaBuf, UINT32 shaBufLen, BYTE *digest)
{
    TSS_HHASH hHash;
    BYTE *apiBuf;
    UINT32 apiBufLen;

    Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH,
		TSS_HASH_DEFAULT, &hHash);
    Tspi_Hash_UpdateHashValue(hHash, shaBufLen, (BYTE *)shaBuf);
    Tspi_Hash_GetHashValue(hHash, &apiBufLen, &apiBuf);
    memcpy (digest, apiBuf, apiBufLen);
    Tspi_Context_FreeMemory(hContext, apiBuf);
    Tspi_Context_CloseObject(hContext, hHash);
}
