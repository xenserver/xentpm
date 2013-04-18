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
#include <trousers/trousers.h>

#define KEY_FILE "/opt/xensource/tpm/tpm_key"
#define KEY_SIZE 20
#define KEY_HEX_SIZE 40
int generate_aik(char *aik_blob_path); 
int get_aik_pem(char *aik_blob_path);
int get_aik_tcpa(char *aik_blob_path); 
int tpm_quote(char *nonce, char *aik_blob_file);
int tpm_owned();
int take_ownership();
int tpm_challenge(char *aik_blob_file, char *challenge);
int get_ek();
int get_ekcert();
int print_base64(void* data, uint32_t len);
int read_tpm_key(unsigned char *key, int keyLen);
int tpm_free_context(TSS_HCONTEXT hContext,
        TSS_HPOLICY hTPMPolicy);
int tpm_create_context(TSS_HCONTEXT *hContext, TSS_HTPM *hTPM, TSS_HKEY *hSRK,
        TSS_HPOLICY *hTPMPolicy, TSS_HPOLICY *hSrkPolicy); 
int load_aik_tpm(char * aik_blob_path, TSS_HCONTEXT hContext,
        TSS_HKEY hSRK, TSS_HKEY* hAIK);
#endif
