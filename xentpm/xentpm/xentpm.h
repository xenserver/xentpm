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
#include <openssl/err.h>
#include <trousers/trousers.h>

#define CONFIG_FILE "/opt/xensource/tpm/config"
#define CITRIX_LABEL_STR "citrix"
#define GET_SHORT_UINT16(buf,offset) \
    (((buf)[(offset)] << CHAR_BIT) | (buf)[(offset) + 1])


#define MAX_CONFIG_KEY_LEN 1024
#define CONFIG_TPM_PASSWORD_KEY "password"
#ifndef CHAR_BIT 
#define CHAR_BIT 8
#endif
/* Error Codes  */
//TODO : change names to XENTPM_E_*
#define XEN_SUCCESS              0
#define XEN_INTERNAL_ERR        -3
#define XEN_CERT_ERR            -4
#define XEN_CERT_PARSE_ERR      -5
#define XEN_CONFIG_KEY_ERR      -6
#define XEN_CONFIG_FILE_ERR     -7
#define XEN_MISSING_AIK_ERR     -8
#define XEN_CORRUPT_AIK_ERR     -9


/*  XenTPM internal function
 */

#define CITRIX_UUID_AIK  {'c','i','t','r','i','x', 'u', 'u', 'i', 'd', 0}

/* XenTPM Client calls via Python */

int generate_aik( char* b64_xen_cert); 
int tpm_quote(char *nonce);
int tpm_challenge(char *challenge);

/* From Python plugin Internal*/
int get_aik_pem();
int get_aik_tcpa(); 
int tpm_owned();
int take_ownership();
int get_endorsment_key();
int get_endorsment_keycert();

/* Utils */
int print_base64(void* data, uint32_t len);
int read_tpm_key(unsigned char *key, int key_len);
BYTE* base64_decode(char *in, int * out_len);
void sha1(TSS_HCONTEXT context, void *shabuf, UINT32 shabuf_len, BYTE *digest);
int get_config_key(const char* key, char* val, int max_val_len);

/* Context Init and free */
int tpm_free_context(TSS_HCONTEXT context,
        TSS_HPOLICY tpm_handlePolicy);
int tpm_create_context(TSS_HCONTEXT *context, TSS_HTPM *tpm_handle, 
        TSS_HKEY *srk_handle, TSS_HPOLICY *tpm_policy, TSS_HPOLICY *srk_policy); 
int  tpm_init_context(TSS_HCONTEXT *context, TSS_HTPM *tpm_handle,
            TSS_HPOLICY *tpm_policy); 


/* Aik load/register/unregister in Trousers
 * */
int load_aik_tpm(TSS_HCONTEXT context,
        TSS_HKEY srk_handle, TSS_HKEY* aik_handle);
int unregister_aik_uuid(TSS_HCONTEXT context);
int register_aik_uuid(TSS_HCONTEXT context, TSS_HKEY aik_handle);


#endif
