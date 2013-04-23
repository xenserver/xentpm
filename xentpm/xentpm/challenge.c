/*
 * aikrespond.c
 *
 * Third step in proving an AIK is valid without using a Privacy CA.
 *
 * Reads AIK blob file and challenge file from challenger. Decrypts
 * encrypted data and outputs to a file, which should be sent back to
 * challenger. Successful decryption proves that it is a real AIK.
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

/* Foolowing function is called when
 * TPM challange api is called by user
 * input is the challange encoded in base_64
 * */


int tpm_challenge(char *aik_blob_path, char *b64_challenge)
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_HKEY hAIK;
    TSS_HPOLICY	hTPMPolicy;
    TSS_HPOLICY	hSrkPolicy;
    BYTE *response;
    UINT32 responseLen;
    BYTE *asymCAData;
    UINT32 asymCADataLen;
    BYTE *symCAData;
    UINT32 symCADataLen;
    BYTE* challengeBuf = NULL;
    int challengeLen;
    int	result;

    syslog(LOG_INFO, "Recieved a Challange");

    result = tpm_create_context(&hContext, &hTPM, &hSRK, 
            &hTPMPolicy, &hSrkPolicy); 

    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error in aik context for generating aik");
        return result;
    }
    

    if ( (result = load_aik_tpm(aik_blob_path, hContext,  hSRK, &hAIK)) != 0) {
        syslog(LOG_ERR, "Unable to readn file %s\n", aik_blob_path);
        return result;
    }
    
    challengeBuf = base64_decode(b64_challenge, &challengeLen);

    if (!challengeBuf) {
        syslog(LOG_ERR, "Unable to b64 decode challange \n");
        return 1;
    }
        

    // Parse the decoded challange from client
    //  Challange has following format
    //  4 byte size  // ASYM_CA_LENGHT
    //  ASYM_CA_CONTENT  
    //  4 bytes size
    //  SYM_CA_Structure 
   
    
    //== Following are the structures we expect from the client
    
    /* SYM_CA_Structure Encrypt with EK */
    /*
     * Creating the AYSM_CA_CONTENT for ecrypting the session key
     * 
     typedef struct  TPM_ASYM_CA_CONTENTS {
         TPM_SYMMETRIC_KEY sessionKey; // 
         TPM_DIGEST idDigest;
     } TPM_ASYM_CA_CONTENTS;

     typedef struct tdTPM_SYMMETRIC_KEY {
        TPM_ALGORITHM_ID algId;
        TPM_ENC_SCHEME encScheme;
        UINT16 size;
        BYTE* data;
     } TPM_SYMMETRIC_KEY;
     **/
    
    
    if (challengeLen < 2*sizeof(UINT32))
        goto badchal;

    // First read the ASYM_CA_CONTENT    
    asymCADataLen = ntohl(*(UINT32*)challengeBuf);
    asymCAData = challengeBuf + sizeof(UINT32);
    challengeBuf += asymCADataLen + sizeof(UINT32);

    if (challengeLen < asymCADataLen+ 2*sizeof(UINT32))
        goto badchal;
    
    // Rad the TPM_SYMMETRIC_KEY data 
    symCADataLen = ntohl(*(UINT32*)challengeBuf);
    
    if (challengeLen != asymCADataLen + symCADataLen + 2*sizeof(UINT32))
        goto badchal;
    symCAData = challengeBuf + sizeof(UINT32);

    // Decrypt challenge data
    
    result = Tspi_TPM_ActivateIdentity(hTPM, hAIK, asymCADataLen, asymCAData,
                                       symCADataLen, symCAData, &responseLen, &response); 
    
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_TPM_ActivateIdentity failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    if ((result = print_base64(response,responseLen)) != 0) {
        syslog(LOG_ERR, "Error in converting B64 %s and %d ",__FILE__,__LINE__);
        return 1;
    }

    result = tpm_free_context(hContext,hTPMPolicy);

    if (result != TSS_SUCCESS ) {
        syslog(LOG_ERR, "Error in aik context for free %s and %d ",__FILE__,__LINE__);
        return result;
    }
    
    syslog(LOG_INFO, "Success in response!\n");
    return 0;
    
badchal:
    syslog(LOG_ERR, "Challenge file format is wrong\n");
    return 1;
}
