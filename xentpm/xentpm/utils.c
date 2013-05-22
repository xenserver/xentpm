/*
 * Copyright (C) 2006-2009 Citrix Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "xentpm.h"
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#define AIK_STORAGE_TYPE TSS_PS_TYPE_SYSTEM

/* Internal function */

static int get_key_bytes(unsigned char * md, unsigned char * buf);
static char get_val(char c);

/* Base64 conversion */

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
        syslog(LOG_ERR, "Error in memory allocation size %d at %s and %d ", 
        bptr->length, __FILE__, __LINE__);
        return XENTPM_E_INTERNAL;
    } 
    memcpy(b64Buff, bptr->data, bptr->length-1);
    b64Buff[bptr->length-1] = 0;
    BIO_free_all(b64);
    printf(b64Buff);
    free(b64Buff);
    return XENTPM_SUCCESS;
}

int read_tpm_key(unsigned char *key, int keyLen)
{
    unsigned char key_buf[2*SHA_DIGEST_LENGTH + 1]; // sha1 in hex
    int result = 0;;

    if ((result = get_config_key(CONFIG_TPM_PASSWORD_KEY, (char*)key_buf, 
        sizeof(key_buf))) != 0) {
        goto out;
    }
    
    if ((result = get_key_bytes(key,key_buf)) != 0) {
        syslog(LOG_ERR, "Error converting key bytes %s\n",key);
        result = XENTPM_E_CONFIG_KEY;
    }
out:
    return result;
}

/* convert sha1 hex string to sha1 bytes
*/
static int get_key_bytes(unsigned char * md, unsigned char * buf)
{
    int i;
    char t1;
    char t2;
    for (i = 0;i < SHA_DIGEST_LENGTH; i++) {
        t1 = get_val(buf[i*2]);    
        t2 = get_val(buf[i*2+1]);
        if( t1 < 0 || t2 < 0) {
            return 1;  
        }
        md[i] = (t1 << 4) + t2; 
    }
    return 0;
}

/* Hex to Decimal */
static char get_val(char c) 
{
    if (isdigit(c))
        return  ( c - '0');
    else if (isupper(c))
        return  (c - 'A' + 10);
    else if (islower(c))
        return (c - 'a' + 10);
    return -1;
}


int unregister_aik_uuid(TSS_HCONTEXT context)
{
    TSS_HKEY aik_handle; 
    int	    result;
    TSS_UUID aik_uuid = CITRIX_UUID_AIK ;

    result = Tspi_Context_GetKeyByUUID(context, AIK_STORAGE_TYPE,
            aik_uuid, &aik_handle);
    if (result == TSS_E_PS_KEY_NOTFOUND) {
        syslog(LOG_INFO, "unregister_aik_uuid not found --not an error");
        return TSS_SUCCESS;
    }        
    else if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "unregister_aik_uuid GetKeyUUID failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        return result;
    }
    
    result = Tspi_Context_UnregisterKey(context, AIK_STORAGE_TYPE,
            aik_uuid, &aik_handle);
    return result;
}

int register_aik_uuid(TSS_HCONTEXT context, TSS_HKEY aik_handle) 
{

    TSS_UUID aik_uuid = CITRIX_UUID_AIK ;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    int	result;

    result = Tspi_Context_RegisterKey(context, aik_handle, AIK_STORAGE_TYPE,
            aik_uuid, TSS_PS_TYPE_SYSTEM, SRK_UUID);

    if (result == TSS_E_KEY_ALREADY_REGISTERED) {
        syslog(LOG_ERR, "Tspi_Context_RegisterKey(UUID) already registered 0x%X %s", 
                result, Trspi_Error_String(result));
        return TSS_SUCCESS;
    }        
    else if (result != TSS_SUCCESS) {       
        Tspi_Context_UnregisterKey(context, AIK_STORAGE_TYPE,
                aik_uuid, &aik_handle);
        syslog(LOG_ERR, "Tspi_Context_RegisterKey(UDD) failed with 0x%X %s", 
                result, Trspi_Error_String(result));
    } 
    return result;
}

int load_aik_tpm( TSS_HCONTEXT context,
        TSS_HKEY srk_handle, TSS_HKEY* aik_handle)
{
    int	result;
    TSS_UUID aik_uuid = CITRIX_UUID_AIK ;
    //BYTE   *aik_blob;
    //UINT32 aik_blob_len;
    result = Tspi_Context_GetKeyByUUID(context, AIK_STORAGE_TYPE,
            aik_uuid, aik_handle);
    if (result != TSS_SUCCESS) {
        syslog(LOG_INFO, "Load_aik_tpm ..key not found \n "); 
        return result;
    }
    result = Tspi_Key_LoadKey((*aik_handle), srk_handle);

    /*result = Tspi_GetAttribData( *(aik_handle), TSS_TSPATTRIB_KEY_BLOB,
            TSS_TSPATTRIB_KEYBLOB_BLOB,
            &aik_blob_len, &aik_blob);

    if ( result != TSS_SUCCESS ) {
        syslog(LOG_ERR, "Load_aik_tpm Tspi_GetAttribData failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        return result;
    }

    result = Tspi_Context_LoadKeyByBlob(context, srk_handle, aik_blob_len,
            aik_blob, aik_handle);
  

    result = Tspi_Context_LoadKeyByUUID(context, AIK_STORAGE_TYPE,
            aik_uuid, aik_handle);
   */
  if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByBlob(AIK) failed with 0x%X %s", 
                result, Trspi_Error_String(result));
        result = XENTPM_E_CORRUPT_AIK; // unable to load aik 
    }
    return result;
}

/* base64 decode 'in' string */

BYTE* base64_decode(char *in, int * outlen)
{
    BIO *bmem, *b64;
    BYTE *out;
    UINT32 buflen;
    buflen = strlen(in);
    out = (BYTE*)malloc(buflen+1);
    
    if (!out) {
        syslog(LOG_ERR, "Unable to allocate memory %s and %d \n",
            __FILE__, __LINE__);
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

/* Trim white space in-place */
static char* trim_white_space(char *str)
{
    char *end;

    /*Trim leading space*/
    while(isspace(*str)) str++;

    if(*str == 0)
        return str;

    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while(end > str && isspace(*end)) end--;

    /* Write new null terminator*/
    *(end+1) = 0;

    return str;
}

/* Read a key from config file  */
int get_config_key(const char* key, char* val, int max_val_len)
{
    char *k;
    char *v;
    int ret;
    char buffer[MAX_CONFIG_KEY_LEN];

    FILE* fp = fopen(CONFIG_FILE,"r");

    if(!fp) {
        syslog(LOG_ERR, "Unable to open %s for reading err: %s \n",
                CONFIG_FILE, strerror(errno));
        return XENTPM_E_CONFIG_FILE;
    }

    while (fgets(buffer, sizeof buffer, fp) != NULL) {
        if (buffer[0] == '#' || buffer[0] == '\n' ||  buffer[0] == '\r')
            continue;
        k = strtok(buffer, "=\r\n");
        if (!k)
            return XENTPM_E_CONFIG_FILE;
        trim_white_space(k);
        if(((ret = strcasecmp(k, key)) == 0) ) {
            v = strtok(NULL, "\r\n");
            if (v) {
                trim_white_space(v);
                if (strlen(v) >  max_val_len) {
                    syslog(LOG_ERR, "Key %s value %s bigger then expected value \
                            size \n", key,v );
                    goto err;
                }
                strcpy(val, v);
                fclose(fp);
                return XENTPM_SUCCESS;
            }
        }
    }
err:
    syslog(LOG_ERR, "Unable to read key  %s \n", key);
    fclose(fp);
    return XENTPM_E_CONFIG_KEY;
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

    /* Caller will free all */
    goto out;

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
        goto out;
    }

    result = tpm_init_context(context, tpm_handle, tpm_policy);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_Create failed with 0x%X %s", 
            result, Trspi_Error_String(result));
        goto out;
    }


    result = Tspi_Context_LoadKeyByUUID((*context),
            TSS_PS_TYPE_SYSTEM, SRK_UUID, srk_handle);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Context_LoadKeyByUUID(TSS_PS_TYPE_SYSTEM, SRK_UUID) \
            failed with 0x%X %s", result, Trspi_Error_String(result));
        goto error_free;
    }

   /*  result = Tspi_GetPolicyObject((*srk_handle), TSS_POLICY_USAGE, srk_policy); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_GetPolicyObject(SRK, TSS_POLICY_USAGE) \
            failed with 0x%X %s", result, Trspi_Error_String(result));
        goto error_free;
    }
    */
    result = Tspi_Context_CreateObject((*context), TSS_OBJECT_TYPE_POLICY,
        TSS_POLICY_USAGE, srk_policy);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_CreatObject(SRK, TSS_POLICY_USAGE) \
            failed with 0x%X %s", result, Trspi_Error_String(result));
        goto error_free;
    }

    result = Tspi_Policy_SetSecret(*srk_policy, TSS_SECRET_MODE_SHA1,
                (UINT32)(sizeof(tpm_key)), (BYTE*)tpm_key);
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_SetSecret(SRK) failed with 0x%X %s", 
            result, Trspi_Error_String(result));
    }

    result = Tspi_Policy_AssignToObject((*srk_policy), (*srk_handle)); 
    if (result != TSS_SUCCESS) {
        syslog(LOG_ERR, "Tspi_Policy_AssignToObject failed with 0x%X %s", 
            result, Trspi_Error_String(result));
    }

    /* Caller will free all */
    goto out; 
error_free:
    tpm_free_context(*context, *tpm_policy);
out:
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
