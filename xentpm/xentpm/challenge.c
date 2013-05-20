/*
 * Third step in proving an AIK is valid without using a Privacy CA.
 *
 * Reads AIK blob file and challenge file from challenger. Decrypts
 * encrypted data and outputs to a file, which should be sent back to
 * challenger. Successful decryption proves that it is a real AIK.
 */

#include <arpa/inet.h>
#include "xentpm.h"

/* Foolowing function is called when
 * TPM challange api is called by user
 * input is the challange encoded in base_64
 */

int tpm_challenge(char *b64_challenge)
{
    TSS_HCONTEXT context;
    TSS_HTPM tpm_handle;
    TSS_HKEY srk_handle;
    TSS_HKEY aik_handle;
    TSS_HPOLICY	tpm_policy;
    TSS_HPOLICY	srk_policy;
    BYTE *response;
    UINT32 responseLen;
    BYTE *asymCA_data;
    UINT32 asymCA_data_len;
    BYTE *symCA_data;
    UINT32 symCA_data_len;
    BYTE* challenge = NULL;
    int challenge_len;
    int	result;

    syslog(LOG_INFO, "Recieved a Challange");
    
    challenge = base64_decode(b64_challenge, &challenge_len);
    if (!challenge) {
        syslog(LOG_ERR, "Unable to b64 decode challange \n");
        result = TSS_E_BAD_PARAMETER;
        goto free_context;
    }

    result = tpm_create_context(&context, &tpm_handle, &srk_handle, 
            &tpm_policy, &srk_policy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Error in aik context for generating aik");
        goto out;
    }

    if ((result = load_aik_tpm(context, 
            srk_handle, &aik_handle)) != 0) {
        syslog(LOG_ERR, "challange Unable to load citrix aik");
        goto free_context;
    }
    /* Parse the decoded challange from client
     *  Challange has following format
     *  4 byte size  // ASYM_CA_LENGHT
     *  ASYM_CA_CONTENT  
     *  4 bytes size
     *  SYM_CA_Structure 
     */
    
    /* Following are the structures we expect from the client */
    
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
    
    if (challenge_len < 2*sizeof(UINT32)){
        result = TSS_E_BAD_PARAMETER;
        syslog(LOG_ERR, "Challenge Length too small\n");
        goto free_context;
    }
    /* First read the ASYM_CA_CONTENT   */
    asymCA_data_len = ntohl(*(UINT32*)challenge);
    asymCA_data = challenge + sizeof(UINT32);
    challenge += (asymCA_data_len + sizeof(UINT32));

    if (challenge_len < asymCA_data_len + 2*sizeof(UINT32)) {
        syslog(LOG_ERR, "Challenge incomplete\n");
        result = TSS_E_BAD_PARAMETER;
        goto free_context;
    }
    /* Rad the TPM_SYMMETRIC_KEY data */
    symCA_data_len = ntohl(*(UINT32*)challenge);
    if (challenge_len != asymCA_data_len + symCA_data_len + 2*sizeof(UINT32)) {
        syslog(LOG_ERR, "Challenge does not have SYM and ASYM keys\n");
        result = TSS_E_BAD_PARAMETER;
        goto free_context;
    }
   
    symCA_data = challenge + sizeof(UINT32);
    /* Decrypt challenge data */
    result = Tspi_TPM_ActivateIdentity(tpm_handle, aik_handle, asymCA_data_len, 
                asymCA_data, symCA_data_len, symCA_data, &responseLen,
                &response); 
    
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_TPM_ActivateIdentity failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        goto free_context;
    }

    if ((result = print_base64(response, responseLen)) != 0) {
        syslog(LOG_ERR, "Error in converting B64 %s and %d ",
            __FILE__,__LINE__);
        goto free_context;
    }

    syslog(LOG_INFO, "XenTPM challange success!\n");
    
free_context:
    Tspi_Context_CloseObject(context, srk_policy);
    tpm_free_context(context, tpm_policy);
out:
    return result;
}
