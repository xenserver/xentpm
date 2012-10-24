/* Certificate creation for TPM EK.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#endif

#define TPMPASSWD "xenroot"

int mkcert(X509 **x509p);
int add_ext(X509 *cert, int nid, char *value);
EVP_PKEY* read_rsa_privkey();
EVP_PKEY* read_rsa_pubkey();
int verify_cert(X509*  x509);
int read_tpm_cert(char* certfile);
void log_msg(char* file,int line,char *msg, ...);
void exit_status(int status);


#ifndef XEN_PRIVATE_KEY
#define XEN_PRIVATE_KEY "/etc/ssh/ssh_host_rsa_key"
#endif

#ifndef TPMCERTDIR
#define TPMCERTDIR "/opt/tpm/"
#endif
#ifndef TPMCERTFILE
#define TPMCERTFILE "/opt/tpm/tpm.cert"
#endif

#ifndef XENCERTFILE
#define XENCERTFILE "/opt/tpm/xentpm.cert"
#endif

#define XEN_PUBKEY "/opt/tpm/xen.pub"

#define LOG_FILE  "/tmp/xen_tpm_agent.log"

/* Generate a pu key in PEM format
 *openssl rsa -in ssh_host_rsa_key -pubout > /etc/tpm/xen.pub
 */

#define BSIZE	128
#define CKERR	if (result != TSS_SUCCESS) goto error

/* Definitions from section 7 of
 * TCG PC Client Specific Implementation Specification
 * For Conventional BIOS
 */
#define TCG_TAG_PCCLIENT_STORED_CERT		0x1001
#define TCG_TAG_PCCLIENT_FULL_CERT		0x1002
#define TCG_TAG_PCCLIENT_PART_SMALL_CERT	0x1003
#define TCG_FULL_CERT				0
#define TCG_PARTIAL_SMALL_CERT			1


#define TPMPASSWD "xenroot"

/*
 *Function tries to read a TPM
 *certificate from NV_RAM 
 * return 0 on success
 * 
 * */

FILE *log_filp;

int read_tpm_cert(char* certfile)
{
    TSS_HCONTEXT	hContext;
    TSS_HNVSTORE	hNV;
    FILE		    *f_out;
    UINT32	    	blobLen;
    UINT32		    nvIndex = TSS_NV_DEFINED|TPM_NV_INDEX_EKCert;
    UINT32		    offset;
    UINT32		    ekOffset;
    UINT32		    ekbufLen;
    BYTE		    *ekbuf;
    BYTE		    *blob;
    UINT32		    tag, certType;
    int		        result;

    result = Tspi_Context_Create(&hContext); CKERR;
    result = Tspi_Context_Connect(hContext, NULL); CKERR;
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNV); CKERR;
    result = Tspi_SetAttribUint32(hNV, TSS_TSPATTRIB_NV_INDEX, 0, nvIndex); CKERR;

    /* Try reading certificate header from NV memory */
    blobLen = 5;
    result = Tspi_NV_ReadValue(hNV, 0, &blobLen, &blob);
    if (result != TSS_SUCCESS) {
        /* Try again with authorization */
        TSS_HPOLICY	hNVPolicy;
        result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hNVPolicy); CKERR;
        result = Tspi_Policy_SetSecret(hNVPolicy,TSS_SECRET_MODE_PLAIN,
                (UINT32)strlen(TPMPASSWD),(BYTE*)TPMPASSWD);
        result = Tspi_Policy_AssignToObject(hNVPolicy, hNV); CKERR;
        blobLen = 5;
        result = Tspi_NV_ReadValue(hNV, 0, &blobLen, &blob);
    }
    if (result != TSS_SUCCESS) {
        // printf("Error %s\n",Trspi_Error_String(result));
        //log_msg(__FILE__,__LINE__,"Unable to read EK Certificate from TPM\n");
        goto error;
    }
    if (blobLen < 5)
        goto parseerr;
    tag = (blob[0]<<8) | blob[1];
    if (tag != TCG_TAG_PCCLIENT_STORED_CERT)
        goto parseerr;
    certType = blob[2];
    if (certType != TCG_FULL_CERT)
        goto parseerr;
    ekbufLen = (blob[3]<<8) | blob[4];
    /*	result = Tspi_Context_FreeMemory (hContext, blob); CKERR; */
    offset = 5;
    blobLen = 2;
    result = Tspi_NV_ReadValue(hNV, offset, &blobLen, &blob); CKERR;
    if (blobLen < 2)
        goto parseerr;
    tag = (blob[0]<<8) | blob[1];
    if (tag == TCG_TAG_PCCLIENT_FULL_CERT) {
        offset += 2;
        ekbufLen -= 2;
    } else if (blob[0] != 0x30)	/* Marker of cert structure */
        goto parseerr;
    /*	result = Tspi_Context_FreeMemory (hContext, blob); CKERR; */

    /* Read cert from chip in pieces - too large requests may fail */
    ekbuf = malloc(ekbufLen);
    ekOffset = 0;
    while (ekOffset < ekbufLen) {
        blobLen = ekbufLen-ekOffset;
        if (blobLen > BSIZE)
            blobLen = BSIZE;
        result = Tspi_NV_ReadValue(hNV, offset, &blobLen, &blob); CKERR;
        memcpy (ekbuf+ekOffset, blob, blobLen);
        /*		result = Tspi_Context_FreeMemory (hContext, blob); CKERR; */
        offset += blobLen;
        ekOffset += blobLen;
    }

    if ((f_out = fopen (certfile, "wb")) == NULL) {
        log_msg(__FILE__,__LINE__,"Unable to open '%s' for output\n", certfile);
        exit_status (1);
    }

    fwrite (ekbuf, 1, ekbufLen, f_out);
    fclose (f_out);
    return 0;

error:
    // log_msg(__FILE__,__LINE__,"Failure, error code: 0x%x\n", result);
    return 1;
parseerr:
    //log_msg(__FILE__,__LINE__,"Failure, unable to parse certificate store structure\n");
    return 2;
}


/* Read the TPM EK
 * TODO : generate one and insert if does not exist
 * 
 */

EVP_PKEY* get_tpm_ek()
{

    TSS_HCONTEXT	hContext;
    TSS_HTPM    	hTPM;
    TSS_RESULT	    result;
    TSS_HKEY	    hPubek;
    UINT32		    modulusLen;
    UINT32		    e_size;
    BYTE		    *modulus;
    BYTE            *e;
    EVP_PKEY        *pk;
    RSA			    *ekRsa;
    TSS_HPOLICY     ekPolicy;


    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_Context_Create Unable to connect\n", result);
        exit_status(result);
    }
    result = Tspi_Context_Connect(hContext, NULL);
    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_Context_Connect Unable to connectt\n", result);
        exit_status(result);
    }
    result = Tspi_Context_GetTpmObject (hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_Context_GetTpmObject\n", result);
        exit_status(result);
    }

    result = Tspi_TPM_GetPubEndorsementKey (hTPM, FALSE, NULL, &hPubek);

    if (result == TCPA_E_DISABLED_CMD) {

        result = Tspi_GetPolicyObject (hTPM, TSS_POLICY_USAGE, &ekPolicy);
        if (result != TSS_SUCCESS) {
            log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_Context_GetTpmObject\n", result);
            exit_status(result);
        }

        result = Tspi_Policy_SetSecret(ekPolicy, TSS_SECRET_MODE_PLAIN,
                (UINT32)strlen(TPMPASSWD),(BYTE*)TPMPASSWD);

        if (result != TSS_SUCCESS) {
            log_msg(__FILE__,__LINE__,"Error Setting TPM Password %s \n", Trspi_Error_String(result));
            exit_status(result);
        } 
        result = Tspi_TPM_GetPubEndorsementKey (hTPM, TRUE, NULL, &hPubek);
    }

    if (result != TSS_SUCCESS) {
            log_msg(__FILE__,__LINE__,"Error Reading TPM EK %s \n", Trspi_Error_String(result));
            log_msg(__FILE__,__LINE__,"Error Reading TPM EK, check the owner password after enabling the TPM \n");
	    return NULL;
	}

    result = Tspi_GetAttribData (hPubek, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &modulusLen, &modulus);

    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error TPM EK RSA %s \n", Trspi_Error_String(result));
        return NULL;
    }

    if (modulusLen != 256) {
        Tspi_Context_FreeMemory (hContext, modulus);
        log_msg(__FILE__,__LINE__,"Error TPM EK RSA %s \n", Trspi_Error_String(result));
        return NULL;
    }

    result = Tspi_GetAttribData(hPubek, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &e_size, &e);

    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_Context_GetAttr Exponent\n", result);
        Tspi_Context_FreeMemory (hContext, modulus);
        return NULL;
    }

    Tspi_Context_CloseObject (hContext, hPubek);
    ekRsa = RSA_new();
    ekRsa->n = BN_bin2bn (modulus,modulusLen, NULL);
    ekRsa->e = BN_new();
    ekRsa->e = BN_bin2bn(e, e_size, NULL);

    Tspi_Context_FreeMemory (hContext, modulus);
    Tspi_Context_FreeMemory (hContext, e);

    if ((pk=EVP_PKEY_new()) == NULL){
        RSA_free(ekRsa);
        log_msg(__FILE__,__LINE__,"%s","Error creating a EK EVP");
        return NULL;
    }
    if (!EVP_PKEY_assign_RSA(pk,ekRsa)){
        EVP_PKEY_free(pk);
        RSA_free(ekRsa);
        log_msg(__FILE__,__LINE__,"%s","Error inserting ek in EVP");
        return NULL;
    }

    return pk;
}


int main(int argc, char **argv)
{
	BIO *bio_err;
	X509 *x509=NULL;
    FILE * fp = NULL;
    int result;
   
   /*
    result = mkdir(TPMCERTDIR,0700);
        if (errno != EEXIST) {
            log_msg(__FILE__,__LINE__,"%s : %s ","Error Creating Certificate dir ",TPMCERTDIR);
            exit_status(1);
        }
    }*/
    log_filp = fopen(LOG_FILE,"a+");
    
    if (!log_filp) {
        exit_status(1);
    }

    /*read the cert */
    if (read_tpm_cert(TPMCERTFILE) == 0){
        log_msg(__FILE__,__LINE__,"%s"," EK Certificate Found in TPM\n");
        exit_status(0);  
    }  

    log_msg(__FILE__,__LINE__,"%s"," EK Certificate not present in TPM\n");
    log_msg(__FILE__,__LINE__,"%s","Creating a Self Signed Certificate \n");
    /* cert not available in TPM
     * create the cert for EK from Xenserver private key
     * */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings(); 
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);
    
    mkcert(&x509);
    verify_cert(x509);
    
    fp = fopen(XENCERTFILE,"wb");

    //PEM_write_PrivateKey(stdout,pkey,NULL,NULL,0,NULL, NULL);
	//PEM_write_X509(stdout,x509);
    
    if(fp != NULL)
        i2d_X509_fp(fp,x509);
    fclose(fp);
    
    X509_free(x509);
#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();
	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);
	
    log_msg(__FILE__,__LINE__,"%s"," Success::EK Certificate Created\n");
    return(0);
}

int mkcert(X509 **x509p)
{
	X509 *x;
	EVP_PKEY *ek_pk;
	EVP_PKEY *pk;
	X509_NAME *name = NULL;
    
    pk = read_rsa_privkey();
	if ((x = X509_new()) == NULL) {
        log_msg(__FILE__,__LINE__,"%s","Error Allocating Certificate");
        exit_status(1);
    }

    ek_pk = get_tpm_ek();
    
    if (!ek_pk) {
	 EVP_PKEY_free(pk);
        log_msg(__FILE__,__LINE__,"%s","Error Reading TPM Endorsement Key");
        exit_status(1);
    }


	X509_set_version(x,2);
	ASN1_INTEGER_set(X509_get_serialNumber(x),0);
	X509_gmtime_adj(X509_get_notBefore(x),0); /*now*/
	X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*365); /*year*/
	X509_set_pubkey(x,ek_pk);
    name = X509_get_subject_name(x);

	/* This function creates and adds the entry, working out the
	 * correct string type and performing checks on its length.
	 * Normally we'd check the return value for errors...
	 */
	X509_NAME_add_entry_by_txt(name,"C",
				MBSTRING_ASC, "US", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"CN",
				MBSTRING_ASC, "Citrix", -1, -1, 0);

	/* Its self signed so set the issuer name to be the same as the
 	 * subject.
	 */
	X509_set_issuer_name(x,name);

	/* Add various extensions: standard extensions */
	add_ext(x, NID_basic_constraints, "critical,CA:TRUE");
	add_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign");

	add_ext(x, NID_subject_key_identifier, "hash");

	/* Some Netscape specific extensions */
	add_ext(x, NID_netscape_cert_type, "sslCA");

	add_ext(x, NID_netscape_comment, "TPM Cert Xenserver");

	if (!X509_sign(x,pk,EVP_sha1()))
		goto err;

	*x509p = x;
	EVP_PKEY_free(ek_pk);
	EVP_PKEY_free(pk);
    return(1);
err:
	return(0);
}

/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */

int add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);
	return 1;
}

EVP_PKEY* read_rsa_privkey()
{

    FILE *fp = NULL;
    EVP_PKEY *pk;
    RSA *rsa;
    
    fp = fopen(XEN_PRIVATE_KEY,"r");
    if(!fp) {
        log_msg(__FILE__,__LINE__,"%s","Error Reading  private key file");
        return NULL;
    }
    rsa = RSA_new();
    
    if( !PEM_read_RSAPrivateKey(fp, &rsa, NULL,NULL)) {
        RSA_free(rsa);
        fclose(fp);
        log_msg(__FILE__,__LINE__,"%s","Error Reading private Key");
        return NULL;
    }
    fclose(fp);
    if ((pk=EVP_PKEY_new()) == NULL){
        RSA_free(rsa);
        log_msg(__FILE__,__LINE__,"%s","Error creating a new EVP ");
        return NULL;
    }
 
	if (!EVP_PKEY_assign_RSA(pk,rsa)){
		EVP_PKEY_free(pk);
        RSA_free(rsa);
        log_msg(__FILE__,__LINE__,"%s","Error inserting key in EVP");
        return NULL;
    }
    return pk;
}

/*Read public key for xen
 * this key need to generated from private key
 * using openssl commands
 * openssl rsa -in ssh_host_rsa_key -pubout > /etc/tpm/xen.pub
 * TODO: should we do it in program ??
 * */

EVP_PKEY* read_rsa_pubkey()
{

    FILE *fp = NULL;
    EVP_PKEY *pk;
    RSA *rsa;
    
    fp = fopen(XEN_PUBKEY,"r");
    if(!fp) {
        log_msg(__FILE__,__LINE__,"%s","Error Reading key file");
        return NULL;
    }

    rsa = RSA_new();
    
    if( !PEM_read_RSA_PUBKEY(fp, &rsa, NULL,NULL)) {
        ERR_print_errors_fp(stdout);
        log_msg(__FILE__,__LINE__,"%s","Error Reading public Key");
        RSA_free(rsa);
        fclose(fp);
        return NULL;
    }
   	
    fclose(fp);
    
    if ((pk=EVP_PKEY_new()) == NULL){
        RSA_free(rsa);
        return NULL;
    }
 
	if (!EVP_PKEY_assign_RSA(pk,rsa)){
		EVP_PKEY_free(pk);
        RSA_free(rsa);
        log_msg(__FILE__,__LINE__,"%s","Error inserting key in EVP");
        return NULL;
    }
    return pk;
}

/* Test Verify Certificate
 * */
int verify_cert(X509*  x509){
    
    EVP_PKEY * pkey  = NULL;
    pkey = read_rsa_pubkey();
    if(!pkey) {
        log_msg(__FILE__,__LINE__,"%s","Error reading public_key");
        return 0;
    }
    
    if( X509_verify(x509, pkey) <=0 ) {
         ERR_print_errors_fp(stdout);
         log_msg(__FILE__,__LINE__,"%s","Error Verifying certificate");
         abort();
         return 0;
    }
    return 1;
}


void log_msg(char * file, int line, char *msg, ...)
{

		va_list argp;
        time_t t;  
        char buf[strlen(ctime(&t))+ 1];  
        time(&t);  
        snprintf(buf,strlen(ctime(&t)),"%s ", ctime(&t));  
        fprintf(log_filp, "%s ,%s, line %d: ",buf,file,line);
		va_start(argp, msg);
		vfprintf(log_filp, msg, argp);
		va_end(argp);
		fprintf(log_filp, "\n");
}

void exit_status(int status)
{
    if (log_filp) {
        fflush(log_filp);
        fclose(log_filp);
    }
    exit(status);
}   


