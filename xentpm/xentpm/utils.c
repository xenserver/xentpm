#include "xentpm.h"
#include <unistd.h>
#include <string.h>
#include <ctype.h>


static int get_key_bytes(unsigned char * md, unsigned char * buf);
static char get_val(char c);

int print_base64(void* data, UINT32 len)
{

    BIO *bmem, *b64;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, data, len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    char *b64Buff = (char*)malloc(bptr->length);
    
    if (!b64Buff) {
        syslog(LOG_ERR, "Error in memory allocation %s and %d ",__FILE__,__LINE__);
        return 1;
    } 
    memcpy(b64Buff, bptr->data, bptr->length-1);
    b64Buff[bptr->length-1] = 0;
    BIO_free_all(b64);
    printf(b64Buff);
    free(b64Buff);
    return 0;
}

int read_tpm_key(unsigned char *key, int keyLen)
{
    unsigned char key_buf[2*SHA_DIGEST_LENGTH + 1]; // sha1 in hex
    int result;

    if ((result = get_config_key("password", key_buf, sizeof(key_buf))) != 0) {
        return 1;
    }
    
    if ((result = get_key_bytes(key,key_buf)) != 0)  {
        syslog(LOG_ERR, "Error readin key from %s\n",CONFIG_FILE);
        return 1;
    }

    return 0;
}

//convert sha1 hex string to sha1 bytes

static int get_key_bytes(unsigned char * md, unsigned char * buf)
{
    int i;
    char t1;
    char t2;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        t1 = get_val(buf[i*2]);    
        t2 = get_val(buf[i*2+1]);
        if( t1 < 0 || t2 < 0) {
            return 1;  
        }
        md[i] = (t1 << 4) + t2; 
    }
    return 0;
}

static char get_val(char c) 
{
    char result;
    if (isdigit(c))
        result = c-'0';
    else if (isupper(c))
        result = c-'A' + 10;
    else if (islower(c))
        result = c-'a' + 10;
    else
        return -1;
    return result;
}

int load_aik_tpm(char * aik_blob_path, TSS_HCONTEXT hContext,
        TSS_HKEY hSRK, TSS_HKEY* hAIK)
{
    FILE *f_in;
    BYTE *aikBlob;
    UINT32 aikBlobLen;
    int	result;
    
    if ((f_in = fopen(aik_blob_path, "rb")) == NULL) {
        syslog(LOG_ERR, "Unable to open file %s\n", aik_blob_path);
        return 1;
    }
    fseek(f_in, 0, SEEK_END);
    aikBlobLen = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);
    aikBlob = malloc(aikBlobLen);
    
    if (!aikBlob) {
        syslog(LOG_ERR, "Unable to allocate memory %s and %d \n",__FILE__,__LINE__);
        return 1;
    }

    if (fread(aikBlob, 1, aikBlobLen, f_in) != aikBlobLen) {
        syslog(LOG_ERR, "Unable to readn file %s\n", aik_blob_path);
        return 1;
    }
    fclose(f_in);
    
    result = Tspi_Context_LoadKeyByBlob(hContext, hSRK, aikBlobLen, aikBlob, hAIK); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByBlob(AIK) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }
    
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByBlob(AIK) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }
    free(aikBlob);
    return 0;
}

 /* Decode the 'in' string
  * */

BYTE* base64_decode(char *in, int * outLen)
{
    BIO *bmem, *b64;
    BYTE *out;
    UINT32 bufLen;
    bufLen = strlen(in);
    out = (BYTE*)malloc(bufLen+1);
    if (!out) {
        syslog(LOG_ERR, "Unable to allocate memory %s and %d \n",
            __FILE__,__LINE__);
        return NULL;
    }
    memset(out, 0, bufLen + 1);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(in, bufLen);
    bmem = BIO_push(b64, bmem);
    *outLen = BIO_read(bmem, out, bufLen);
    out[bufLen] = '\0';
    BIO_free_all(bmem);
    return out;
}

void
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

int get_config_key(const char* key, char* val, int max_val_len)
{
    char *k;
    char *v;
    int ret;
    char buffer[1024];

    FILE* fp = fopen(CONFIG_FILE,"r");

    if(!fp) {
        syslog(LOG_ERR, "Unable to open %s for reading\n", CONFIG_FILE);
        return 1;
    }

    while (fgets(buffer, sizeof buffer, fp) != NULL) {

        if(buffer[0]=='#' || buffer[0] =='\n' ||  buffer[0] =='\r' )
            continue;
        k = strtok(buffer, "=\r\n");
        if ( k && ((ret = strcmp(k, key))== 0) ) {
            v = strtok(NULL, "\r\n");
            if (v) {
                strncpy(val, v, max_val_len);
                fclose(fp);
                return 0;
            }
        }
    }
    fclose(fp);
    return 1;
}


int  tpm_init_context(TSS_HCONTEXT *hContext, TSS_HTPM *hTPM,
            TSS_HPOLICY *hTPMPolicy) 
{
    int result;
    BYTE tpm_key[SHA_DIGEST_LENGTH];    
    
    if ((result = read_tpm_key(tpm_key,SHA_DIGEST_LENGTH)) != 0) {
        syslog(LOG_ERR, "TPM Key Not Found \n");
        return TSS_E_FAIL;
    }

    result = Tspi_Context_Create(hContext); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_Create failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        return result;
    }
    result = Tspi_Context_Connect((*hContext), NULL);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_Connect failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Context_GetTpmObject((*hContext), hTPM); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_GetTpmObject failed with 0x%X %s", 
                result, Trspi_Error_String(result));                                                               
        return result;
    }

    result = Tspi_Context_CreateObject((*hContext), TSS_OBJECT_TYPE_POLICY,         
            TSS_POLICY_USAGE, hTPMPolicy);                                          
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CreateObject(TSS_OBJECT_TYPE_POLICY) failed \
                with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_AssignToObject((*hTPMPolicy), (*hTPM));                    
    if (result != TSS_SUCCESS) {                                                    
        syslog(LOG_ERR, "Tspi_Policy_AssignToObject(TPM) failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_SetSecret((*hTPMPolicy), TSS_SECRET_MODE_SHA1,             
            (UINT32)(sizeof(tpm_key)),(BYTE*)tpm_key);                          
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_SetSecret failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        return result;
    }   

    return result;
}


int tpm_create_context(TSS_HCONTEXT *hContext, TSS_HTPM *hTPM, TSS_HKEY *hSRK,
        TSS_HPOLICY *hTPMPolicy, TSS_HPOLICY *hSrkPolicy) 
{

    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    int result;
    BYTE tpm_key[SHA_DIGEST_LENGTH];    
    
    if ((result = read_tpm_key(tpm_key,SHA_DIGEST_LENGTH)) != 0) {
        syslog(LOG_ERR, "TPM Key Not Found \n");
        return TSS_E_FAIL;
    }

    result =  tpm_init_context(hContext, hTPM, hTPMPolicy);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_Create failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }


    result = Tspi_Context_LoadKeyByUUID((*hContext),
            TSS_PS_TYPE_SYSTEM, SRK_UUID, hSRK);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByUUID(TSS_PS_TYPE_SYSTEM, SRK_UUID) \
            failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_GetPolicyObject((*hSRK), TSS_POLICY_USAGE, hSrkPolicy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetPolicyObject(SRK, TSS_POLICY_USAGE) \
            failed with 0x%X %s", result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Policy_SetSecret(*hSrkPolicy, TSS_SECRET_MODE_SHA1,
                (UINT32)(sizeof(tpm_key)),(BYTE*)tpm_key);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_SetSecret(SRK) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }

    return TSS_SUCCESS;
}

int tpm_free_context(TSS_HCONTEXT hContext,
        TSS_HPOLICY hTPMPolicy)
{
    int result ;
    result = Tspi_Context_CloseObject(hContext,hTPMPolicy);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CloseObject failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }
    result = Tspi_Context_FreeMemory (hContext,NULL);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_FreeMemory failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }
    result = Tspi_Context_Close(hContext);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_Close failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        return result;
    }
    return TSS_SUCCESS;
}
