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
#include <trousers/trousers.h>

#define CONFIG_FILE "/opt/xensource/tpm/config"

#define GET_SHORT_UINT16(buf,offset) ( (buf[offset] << sizeof(BYTE)) | buf[offset+1] )

/*  XenTPM internal function
 */

int get_aik_pem(char *aik_blob_path);
int get_aik_tcpa(char *aik_blob_path); 
int tpm_owned();
int take_ownership();
int get_ek();
int get_ekcert();
int print_base64(void* data, uint32_t len);
int read_tpm_key(unsigned char *key, int keyLen);
int tpm_free_context(TSS_HCONTEXT hContext,
        TSS_HPOLICY hTPMPolicy);
int tpm_create_context(TSS_HCONTEXT *hContext, TSS_HTPM *hTPM, TSS_HKEY *hSRK,
        TSS_HPOLICY *hTPMPolicy, TSS_HPOLICY *hSrkPolicy); 
int  tpm_init_context(TSS_HCONTEXT *hContext, TSS_HTPM *hTPM,
            TSS_HPOLICY *hTPMPolicy); 
int load_aik_tpm(char * aik_blob_path, TSS_HCONTEXT hContext,
        TSS_HKEY hSRK, TSS_HKEY* hAIK);
BYTE* base64_decode(char *in, int * outLen);
void
sha1(TSS_HCONTEXT hContext, void *shaBuf, UINT32 shaBufLen, BYTE *digest);
int get_config_key(const char* key, char* val, int max_val_len);



/* XenTPM externally function for Client
 * */
int generate_aik(char *aik_blob_path); 
int tpm_quote(char *nonce, char *aik_blob_file);
int tpm_challenge(char *aik_blob_file, char *challenge);

#endif
