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


// TODO : Error 
// missing key
// corrupt key
//
int load_aik_tpm(char * aik_blob_path, TSS_HCONTEXT context,
        TSS_HKEY srk_handle, TSS_HKEY* aik_handle)
{
    FILE    *f_in;
    BYTE    *aik_blob;
    UINT32  aik_blob_len;
    int	    result;
    
    if ((f_in = fopen(aik_blob_path, "rb")) == NULL) {
        syslog(LOG_ERR, "Unable to open file %s\n", aik_blob_path);
        result = 18; // aik missing from disk 
        goto out;
    }
    
    fseek(f_in, 0, SEEK_END);
    aik_blob_len = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);
    aik_blob = malloc(aik_blob_len);
    
    if (!aik_blob) {
        syslog(LOG_ERR, "Unable to allocate memory %s and %d \n",
            __FILE__,__LINE__);
        result = 1;
        goto close;
    }

    if (fread(aik_blob, 1, aik_blob_len, f_in) != aik_blob_len) {
        syslog(LOG_ERR, "Unable to readn file %s\n", aik_blob_path);
        result = 15; // unable to read ak from disk 
        goto free_blob;
    }
    
    result = Tspi_Context_LoadKeyByBlob(context, srk_handle, aik_blob_len, 
        aik_blob, aik_handle); 
    
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByBlob(AIK) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
    }

 free_blob:
    free(aik_blob);
 close:
    fclose(f_in);
 out:  
   return result;

}

 /* Decode the 'in' string
  * */

BYTE* base64_decode(char *in, int * outlen)
{
    BIO *bmem, *b64;
    BYTE *out;
    UINT32 buflen;
    buflen = strlen(in);
    out = (BYTE*)malloc(buflen+1);
    
    if (!out) {
        syslog(LOG_ERR, "Unable to allocate memory %s and %d \n",
            __FILE__,__LINE__);
        return NULL;
    }
    
    memset(out, 0, buflen + 1);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(in, buflen);
    bmem = BIO_push(b64, bmem);
    *outlen = BIO_read(bmem, out, buflen);
    out[buflen] = '\0';
    BIO_free_all(bmem);
    return out;
}

void
sha1(TSS_HCONTEXT context, void *shabuf, UINT32 shabuf_len, BYTE *digest)
{
    TSS_HHASH hash;
    BYTE *api_buf;
    UINT32 api_buf_len;

    Tspi_Context_CreateObject(context, TSS_OBJECT_TYPE_HASH,
		TSS_HASH_DEFAULT, &hash);
    Tspi_Hash_UpdateHashValue(hash, shabuf_len, (BYTE *)shabuf);
    Tspi_Hash_GetHashValue(hash, &api_buf_len, &api_buf);
    memcpy (digest, api_buf, api_buf_len);
    Tspi_Context_FreeMemory(context, api_buf);
    Tspi_Context_CloseObject(context, hash);
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

/* Init context
 * on error close all object and return fail
 * on sucess return context and policy
 * */

int  tpm_init_context(TSS_HCONTEXT *context, TSS_HTPM *tpm_handle,
            TSS_HPOLICY *tpm_policy) 
{
    int result;
    BYTE tpm_key[SHA_DIGEST_LENGTH];    
    
    if ((result = read_tpm_key(tpm_key,SHA_DIGEST_LENGTH)) != 0) {
        syslog(LOG_ERR, "TPM Key Not Found \n");
        goto out;
    }

    result = Tspi_Context_Create(context); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_Create failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        goto out;
    }
    result = Tspi_Context_Connect((*context), NULL);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_Connect failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        goto out;
    }

    result = Tspi_Context_GetTpmObject((*context), tpm_handle); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_GetTpmObject failed with 0x%X %s", 
                result, Trspi_Error_String(result));                                                               
        goto error_close;
    }

    result = Tspi_Context_CreateObject((*context), TSS_OBJECT_TYPE_POLICY,         
               TSS_POLICY_USAGE, tpm_policy);                                          
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CreateObject(TSS_OBJECT_TYPE_POLICY) failed \
                with 0x%X %s", result, Trspi_Error_String(result));
        goto error_close;
    }

    result = Tspi_Policy_AssignToObject((*tpm_policy), (*tpm_handle));                    
    if (result != TSS_SUCCESS) {                                                    
        syslog(LOG_ERR, "Tspi_Policy_AssignToObject(TPM) failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        goto error_obj;
    }

    result = Tspi_Policy_SetSecret((*tpm_policy), TSS_SECRET_MODE_SHA1,             
            (UINT32)(sizeof(tpm_key)), (BYTE*)tpm_key);                          
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_SetSecret failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        goto error_obj;
    }   

    goto out; // Dont free the objects

 error_obj:
    Tspi_Context_CloseObject(*context, *tpm_policy);
 error_close:
    Tspi_Context_FreeMemory (*context, NULL);
    Tspi_Context_Close(*context);
 out:
    return result;
}


int tpm_create_context(TSS_HCONTEXT *context, TSS_HTPM *tpm_handle, TSS_HKEY *srk_handle,
        TSS_HPOLICY *tpm_policy, TSS_HPOLICY *srk_policy) 
{

    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    int result;
    BYTE tpm_key[SHA_DIGEST_LENGTH];    
    
    if ((result = read_tpm_key(tpm_key, SHA_DIGEST_LENGTH)) != 0) {
        syslog(LOG_ERR, "TPM Key Not Found \n");
        goto error;
    }

    result =  tpm_init_context(context, tpm_handle, tpm_policy);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_Create failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        goto error;
    }


    result = Tspi_Context_LoadKeyByUUID((*context),
            TSS_PS_TYPE_SYSTEM, SRK_UUID, srk_handle);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByUUID(TSS_PS_TYPE_SYSTEM, SRK_UUID) \
            failed with 0x%X %s", result, Trspi_Error_String(result));
        goto error_free;
    }


    result = Tspi_GetPolicyObject((*srk_handle), TSS_POLICY_USAGE, srk_policy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetPolicyObject(SRK, TSS_POLICY_USAGE) \
            failed with 0x%X %s", result, Trspi_Error_String(result));
        goto error_free;
    }

    result = Tspi_Policy_SetSecret(*srk_policy, TSS_SECRET_MODE_SHA1,
                (UINT32)(sizeof(tpm_key)), (BYTE*)tpm_key);
    
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_SetSecret(SRK) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
    }

 error_free:
    tpm_free_context(*context, *tpm_policy);
 error:
    return result;
}

int tpm_free_context(TSS_HCONTEXT context,
        TSS_HPOLICY tpm_policy)
{
    int result ;
    result = Tspi_Context_CloseObject(context, tpm_policy);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_CloseObject failed with 0x%X %s", 
            result, Trspi_Error_String(result));
    }
    result = Tspi_Context_FreeMemory (context, NULL);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_FreeMemory failed with 0x%X %s", 
            result, Trspi_Error_String(result));
    }
    result = Tspi_Context_Close(context);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_Close failed with 0x%X %s", 
            result, Trspi_Error_String(result));
    }
    return result;
}
