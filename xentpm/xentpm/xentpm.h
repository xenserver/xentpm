#ifndef XENTPM_H_
#define XENTPM_H_

#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <errno.h>
#include <syslog.h>
#include <trousers/tss.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <trousers/trousers.h>

#define OWNER_SECRET    "xenroot"

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
#endif
