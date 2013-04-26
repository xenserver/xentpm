#ifndef XENTPM_H_
#define XENTPM_H_

#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <errno.h>
#include <syslog.h>
#include <trousers/tss.h>
#include <tss/tss_defines.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <trousers/trousers.h>

#define CONFIG_FILE "/opt/xensource/tpm/config"

#define CHAR_BIT 8
#define GET_SHORT_UINT16(buf,offset) ( (buf[offset] << CHAR_BIT) | buf[offset+1] )

/*  XenTPM internal function
 */

int get_aik_pem(char *aik_blob_path);
int get_aik_tcpa(char *aik_blob_path); 
int tpm_owned();
int take_ownership();
int get_endorsment_key();
int get_endorsment_keycert();
int print_base64(void* data, uint32_t len);
int read_tpm_key(unsigned char *key, int key_len);
int tpm_free_context(TSS_HCONTEXT context,
        TSS_HPOLICY tpm_handlePolicy);
int tpm_create_context(TSS_HCONTEXT *context, TSS_HTPM *tpm_handle, 
        TSS_HKEY *srk_handle, TSS_HPOLICY *tpm_policy, TSS_HPOLICY *srk_policy); 
int  tpm_init_context(TSS_HCONTEXT *context, TSS_HTPM *tpm_handle,
            TSS_HPOLICY *tpm_policy); 
int load_aik_tpm(char * aik_blob_path, TSS_HCONTEXT context,
        TSS_HKEY srk_handle, TSS_HKEY* aik_handle);
BYTE* base64_decode(char *in, int * out_len);
void sha1(TSS_HCONTEXT context, void *shabuf, UINT32 shabuf_len, BYTE *digest);
int get_config_key(const char* key, char* val, int max_val_len);



/* XenTPM externally called function for Client
 * */
int generate_aik(char *aik_blob_path, char* b64_xeni_key_pem); 
int tpm_quote(char *nonce, char *aik_blob_file);
int tpm_challenge(char *aik_blob_file, char *challenge);

#endif
