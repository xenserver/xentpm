/*
 * aikpublish.c
 *  1)
 *      Publish AIK public key in PEM format and TPM blob format
 *  2)
 *      TPM_KEY blob for the newly generated AIK.
 */

/*
 * Copyright (c) 2009 Hal Finney
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <trousers/tss.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define OWNER_SECRET	"xenroot"

#define CKERR	if (result != TSS_SUCCESS) goto error

#define AIK_PEM_PUB "/opt/tpm/aik_pem.pub"
#define AIK_TCPA_PUB "/opt/tpm/aik_tcpa.pub"
#define AIK_TPM_BLOB "/opt/tpm/aiktpmblob"


#define LOG_FILE  "/tmp/xen_tpm_agent.log"

void log_msg(char* file,int line,char *msg, ...);
void exit_status(int status);

static int verifyCert(char* keyfile, char *certfile);

FILE *log_filp = NULL;
int
main (int ac, char **av)
{
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_HKEY	hSRK;
	TSS_HKEY	hAIK;
	TSS_HKEY	hPCA;
	TSS_HPOLICY	hTPMPolicy;
	TSS_HPOLICY	hSrkPolicy;
	TSS_HPOLICY	hAIKPolicy;
	TSS_UUID	SRK_UUID = TSS_UUID_SRK;
	//BYTE		srkSecret[] = TSS_WELL_KNOWN_SECRET;
	BYTE		n[2048/8];
	FILE		*f_out;
	char		*pass = NULL;
	UINT32		initFlags;
	BYTE		*blob;
	UINT32		blobLen;
    RSA			*aikRsa;
    EVP_PKEY    *aikPk;
    UINT32		e_size;
    BYTE        *e;
    int         i, result;

	
    log_filp = fopen(LOG_FILE,"a+");
    
    if (!log_filp) {
        exit_status(1);
    }

    result = Tspi_Context_Create(&hContext); CKERR;
	result = Tspi_Context_Connect(hContext, NULL); CKERR;
	result = Tspi_Context_LoadKeyByUUID(hContext,
			TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK); CKERR;
	result = Tspi_GetPolicyObject (hSRK, TSS_POLICY_USAGE, &hSrkPolicy); CKERR;
	result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_PLAIN,
			strlen(OWNER_SECRET), (BYTE*)OWNER_SECRET); CKERR;
	result = Tspi_Context_GetTpmObject (hContext, &hTPM); CKERR;
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
			TSS_POLICY_USAGE, &hTPMPolicy); CKERR;
	result = Tspi_Policy_AssignToObject(hTPMPolicy, hTPM);
#ifdef OWNER_SECRET
	result = Tspi_Policy_SetSecret (hTPMPolicy, TSS_SECRET_MODE_PLAIN,
			strlen(OWNER_SECRET), (BYTE*)OWNER_SECRET); CKERR;
#else
	result = Tspi_Policy_SetSecret (hTPMPolicy, TSS_SECRET_MODE_POPUP, 0, NULL); CKERR;
#endif

	/* Create dummy PCA key */
	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048,
					   &hPCA); CKERR;
	memset (n, 0xff, sizeof(n));
	result = Tspi_SetAttribData (hPCA, TSS_TSPATTRIB_RSAKEY_INFO,
		TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, sizeof(n), n); CKERR;

	/* Create AIK object */
	initFlags = TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048;
	if (pass)
		initFlags |= TSS_KEY_AUTHORIZATION;
	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   initFlags, &hAIK); CKERR;
	if (pass) {
		result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
				TSS_POLICY_USAGE, &hAIKPolicy); CKERR;
		result = Tspi_Policy_AssignToObject(hAIKPolicy, hAIK);
		result = Tspi_Policy_SetSecret (hAIKPolicy, TSS_SECRET_MODE_PLAIN,
				strlen(pass)+1, (BYTE*)pass); CKERR;
	}

	/* Generate new AIK */
#ifndef OWNER_SECRET
	{
	/* Work around a bug in Trousers 0.3.1 - remove this block when fixed */
	/* Force POPUP to activate, it is being ignored */
		BYTE *dummyblob1; UINT32 dummylen1;
		if (Tspi_TPM_OwnerGetSRKPubKey(hTPM, &dummylen1, &dummyblob1)
				== TSS_SUCCESS) {
			Tspi_Context_FreeMemory (hContext, dummyblob1);
		}
	}
#endif

	result = Tspi_TPM_CollateIdentityRequest(hTPM, hSRK, hPCA, 0, "",
						 hAIK, TSS_ALG_AES,
						 &blobLen,
						 &blob); CKERR;
	Tspi_Context_FreeMemory (hContext, blob);

	/* Output file with AIK pub key and certs, preceded by 4-byte lengths */
	result = Tspi_GetAttribData (hAIK, TSS_TSPATTRIB_RSAKEY_INFO,
		TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &blobLen, &blob); CKERR;
	
    result = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_RSAKEY_INFO,
        TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &e_size, &e); CKERR;

    aikRsa = RSA_new();
    aikRsa->n = BN_bin2bn (blob, blobLen, NULL);
    aikRsa->e = BN_new();
    aikRsa->e = BN_bin2bn(e, e_size, NULL);

    
    /* Test if the reverse works 
     * and the ans is no it does not ==
     * That is why we need to pass the entire blob
     * char buf[2048] ;
     * int len ;
     * len = BN_bn2bin(aikRsa->n,buf);
     * int res = memcmp(blob,buf,blobLen);
    */

    if ((aikPk = EVP_PKEY_new()) == NULL){
        RSA_free(aikRsa);
        log_msg(__FILE__,__LINE__,"%s","Error creating a AIK EVP");
        exit_status(1);
    }
	if (!EVP_PKEY_assign_RSA(aikPk,aikRsa)){
		EVP_PKEY_free(aikPk);
        RSA_free(aikRsa);
        log_msg(__FILE__,__LINE__,"%s","Error inserting Aik in EVP");
        exit_status(1);
    }
    if ((f_out = fopen (AIK_PEM_PUB, "wb")) == NULL) {
		log_msg(__FILE__,__LINE__, "Unable to open %s for output\n", AIK_PEM_PUB);
		exit_status (1);
	}

    PEM_write_RSA_PUBKEY(f_out, aikRsa);
    fclose(f_out);
    RSA_free(aikRsa);
    
    /*The purpose of this call is to get TCPA_PUBKEY
     *structure of the AIK 
     * this is passed to user for create a challange
     * */
    result = Tspi_GetAttribData (hAIK, TSS_TSPATTRIB_KEY_BLOB,
		TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &blobLen, &blob); CKERR;

    /*Out AIK pubkey Modulus for the challanger*/
	if ((f_out = fopen (AIK_TCPA_PUB, "wb")) == NULL) {
		log_msg(__FILE__,__LINE__, "Unable to open %s for output\n", AIK_TCPA_PUB);
		exit_status (1);
	}
	if (fwrite (blob, 1, blobLen, f_out) != blobLen) {
		log_msg(__FILE__,__LINE__, "Unable to write to %s\n", AIK_TCPA_PUB);
		exit_status (1);
	}
	fclose (f_out);

    /* Output file with AIK blob for TPM future Use */
    /* The output of this call is TPM_KEY(12) struct
     * Used for loading an AIK in TPM
     * */
	result = Tspi_GetAttribData (hAIK, TSS_TSPATTRIB_KEY_BLOB,
		TSS_TSPATTRIB_KEYBLOB_BLOB, &blobLen, &blob); CKERR;
	
	if ((f_out = fopen (AIK_TPM_BLOB, "wb")) == NULL) {
		log_msg(__FILE__,__LINE__, "Unable to open %s for output\n", AIK_TPM_BLOB);
		exit_status (1);
	}
	if (fwrite (blob, 1, blobLen, f_out) != blobLen) {
		log_msg(__FILE__,__LINE__, "Unable to write to %s\n",AIK_TPM_BLOB);
		exit_status (1);
	}
	
    fclose (f_out);
	Tspi_Context_FreeMemory (hContext, blob);
	log_msg(__FILE__,__LINE__,"Created an AIK.pub and TPMAIK\n");
	return 0;
error:
	log_msg(__FILE__,__LINE__,"Failure, error code: 0x%x %s \n", result,Trspi_Error_String(result));
	return 1;
}

/*  Read a key in EVP from keyfile
*/
EVP_PKEY* read_rsa_pubkey(char *keyfile)
{
    FILE *fp = NULL;
    EVP_PKEY *pk;
    RSA *rsa;
    
    fp = fopen(keyfile,"r");
    
    if (!fp) {
        log_msg(__FILE__,__LINE__,"%s","Error Reading key file");
        return NULL;
    }

    rsa = RSA_new();
    
    if (!PEM_read_RSA_PUBKEY(fp, &rsa, NULL,NULL)) {
        log_msg(__FILE__,__LINE__,"%s","Error Reading public Key");
        RSA_free(rsa);
        fclose(fp);
        return NULL;
        }
   	fclose(fp);

    if ((pk=EVP_PKEY_new()) == NULL) {
        RSA_free(rsa);
        return NULL;
        }
 
	if (!EVP_PKEY_assign_RSA(pk,rsa)) {
		EVP_PKEY_free(pk);
        RSA_free(rsa);
        log_msg(__FILE__,__LINE__,"%s","Error inserting key in EVP");
        return NULL;
        }
    return pk;
}



/* Check the certificate from the key */
/* this in internal function for validatin certs from
 * the public key
 * */
static int
verifyCert(char* keyfile, char* certfile)
{
	X509		*tbsX509 = NULL;
	EVP_PKEY	*pkey = NULL;
	int			rslt = -1;
    FILE        *fp = NULL;
	OpenSSL_add_all_algorithms();
	pkey = read_rsa_pubkey(keyfile);
	
    if (!pkey) {
		log_msg(__FILE__,__LINE__,"\n Unable to read rsa public key");
		return 0;
	}
    
    fp = fopen(certfile,"rb");
    
    if(!fp) {
        log_msg(__FILE__,__LINE__,"%s","Error in reading certfile file");
        goto done;
    }

	tbsX509 = d2i_X509_fp(fp, NULL);
    
    if(!tbsX509)  
		goto done;
	
    if (X509_verify (tbsX509, pkey) != 1)
		goto done;

	fclose(fp);
    X509_free (tbsX509);
	tbsX509 = NULL;
	rslt = 0;


done:
	if (pkey)
		EVP_PKEY_free (pkey);
	if (tbsX509)
		X509_free (tbsX509);
	return rslt;
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



