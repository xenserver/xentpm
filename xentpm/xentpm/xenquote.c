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
#include <arpa/inet.h>
static void sha1(TSS_HCONTEXT hContext, void *buf, UINT32 bufLen, BYTE *digest);

int
tpm_quote(char *nonce, char *aik_blob_file)
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_HKEY hAIK;
    TSS_HPOLICY	hSrkPolicy;
    TSS_HPCRS hPCRs;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    TSS_VALIDATION valid;
    TPM_QUOTE_INFO *quoteInfo;
    FILE *f_in;
    UINT32 tpmProp;
    UINT32 npcrMax;
    UINT32 npcrBytes;
    UINT32 npcrs = 0;
    BYTE *buf;
    UINT32 bufLen;
    BYTE *bp;
    BYTE *tmpbuf;
    UINT32 tmpbufLen;
    BYTE chalmd[20];
    BYTE pcrmd[20];
    BIO *bmem, *b64;
    int	i;
    int	result;

    syslog(LOG_INFO, "Request for TPM Quote Generation!\n");

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
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByUUID(SRK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_GetPolicyObject (hSRK, TSS_POLICY_USAGE, &hSrkPolicy); 
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

    result = Tspi_Context_GetTpmObject (hContext, &hTPM); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_GetTpmObject failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    // Base64 decode the nonce
    bufLen = strlen(nonce);
    BYTE* nonceBuf = (BYTE*)malloc(bufLen);
    memset(nonceBuf, 0, bufLen);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(nonce, bufLen);
    bmem = BIO_push(b64, bmem);
    int nonceLen = BIO_read(bmem, nonceBuf, bufLen);
    BIO_free_all(bmem);

    // Hash the nonce
    sha1(hContext, nonceBuf, nonceLen, chalmd);
    free(nonceBuf);

    // Read AIK blob
    if ((f_in = fopen(aik_blob_file, "rb")) == NULL) {
        syslog(LOG_ERR, "Unable to open file %s\n", aik_blob_file);
        return 1;
    }
    fseek(f_in, 0, SEEK_END);
    bufLen = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);
    buf = malloc(bufLen);
    if (fread(buf, 1, bufLen, f_in) != bufLen) {
        syslog(LOG_ERR, "Unable to readn file %s\n", aik_blob_file);
        return 1;
    }
    fclose(f_in);
    
    result = Tspi_Context_LoadKeyByBlob(hContext, hSRK, bufLen, buf, &hAIK); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByBlob(AIK) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    // Create PCR list to be quoted 
    // We will quote all the PCR's
    tpmProp = TSS_TPMCAP_PROP_PCR;
    result = Tspi_TPM_GetCapability(hTPM, TSS_TPMCAP_PROPERTY,
		sizeof(tpmProp), (BYTE *)&tpmProp, &tmpbufLen, &tmpbuf); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_TPM_GetCapability failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    npcrMax = *(UINT32 *)tmpbuf;
    Tspi_Context_FreeMemory(hContext, tmpbuf);
    npcrBytes = (npcrMax + 7) / 8; // PCR MASK
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS,
		TSS_PCRS_STRUCT_INFO, &hPCRs); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CreateObject(PCR) failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

	
    // Create TSS_VALIDATION struct for Quote
    valid.ulExternalDataLength = sizeof(chalmd);
    valid.rgbExternalData = chalmd;

    // Also PCR buffer
    buf = malloc((2 + npcrBytes + 4 + 20 * npcrMax) + valid.ulExternalDataLength);
    *(UINT16 *)buf = htons(npcrBytes);
    for (i=0; i<npcrBytes; i++)
        buf[2+i] = 0;

    for (i=0; i<npcrMax; i++) {
        long pcr = i ;
        result = Tspi_PcrComposite_SelectPcrIndex(hPCRs, pcr); 
        if (result != TSS_SUCCESS) {
            syslog(LOG_ERR, "Tspi_PcrComposite_SelectPcrIndex failed with 0x%X %s", result, Trspi_Error_String(result));
            return result;
        }

        ++npcrs;
        buf[2+(pcr/8)] |= 1 << (pcr%8);
    }

    // Perform Quote
    result = Tspi_TPM_Quote(hTPM, hAIK, hPCRs, &valid);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_TPM_Quote failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    quoteInfo = (TPM_QUOTE_INFO *)valid.rgbData;

    // Fill in the PCR buffer
    bp = buf + 2 + npcrBytes;
    *(UINT32 *)bp = htonl (20*npcrs);
    bp += sizeof(UINT32);
    for (i=0; i<=npcrMax; i++) {
        if (buf[2+(i/8)] & (1 << (i%8))) {
            result = Tspi_PcrComposite_GetPcrValue(hPCRs,
				i, &tmpbufLen, &tmpbuf);
            if (result != TSS_SUCCESS) {
                syslog(LOG_ERR, "Tspi_PcrComposite_GetPcrValue failed with 0x%X %s", result, Trspi_Error_String(result));
                return result;
            }

            memcpy (bp, tmpbuf, tmpbufLen);
            bp += tmpbufLen;
            Tspi_Context_FreeMemory(hContext, tmpbuf);
        }
    }
    bufLen = bp - buf;

    // Test the hash
    sha1(hContext, buf, bufLen, pcrmd);
    if (memcmp(pcrmd, quoteInfo->compositeHash.digest, sizeof(pcrmd)) != 0) {
        // Try with smaller digest length 
        *(UINT16 *)buf = htons(npcrBytes-1);
        memmove(buf+2+npcrBytes-1, buf+2+npcrBytes, bufLen-2-npcrBytes);
        bufLen -= 1;
        sha1(hContext, buf, bufLen, pcrmd);
        if (memcmp(pcrmd, quoteInfo->compositeHash.digest, sizeof(pcrmd)) != 0) {
            syslog(LOG_ERR, "Inconsistent PCR hash in output of quote\n");
            return 1;
        }
    }
    Tspi_Context_FreeMemory(hContext, tmpbuf);

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
    memcpy(&buf[bufLen], valid.rgbValidationData, valid.ulValidationDataLength);
    bufLen += valid.ulValidationDataLength;

    // Base64 encode the response to send back to the caller
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, buf, bufLen);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    char *quoteBuf = (char*)malloc(bptr->length);
    memcpy(quoteBuf, bptr->data, bptr->length-1);
    quoteBuf[bptr->length-1] = 0;
    BIO_free_all(b64);
    printf(quoteBuf);
    free(quoteBuf);

    syslog(LOG_INFO, "Generate TPM Quote Success!\n");
    return 0;
}

static void
sha1(TSS_HCONTEXT hContext, void *buf, UINT32 bufLen, BYTE *digest)
{
    TSS_HHASH hHash;
    BYTE *tmpbuf;
    UINT32 tmpbufLen;

    Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH,
		TSS_HASH_DEFAULT, &hHash);
    Tspi_Hash_UpdateHashValue(hHash, bufLen, (BYTE *)buf);
    Tspi_Hash_GetHashValue(hHash, &tmpbufLen, &tmpbuf);
    memcpy (digest, tmpbuf, tmpbufLen);
    Tspi_Context_FreeMemory(hContext, tmpbuf);
    Tspi_Context_CloseObject(hContext, hHash);
}
