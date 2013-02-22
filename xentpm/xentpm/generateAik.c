/*
 *generate AI
 *  1)
 *      Publish AIK public key in PEM format and TCPA blob format
 *  2)
 *      Write TPM EK and EK cert 
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
#include <trousers/trousers.h>
#define OWNER_SECRET	"xenroot"

#define CKERR	if (result != TSS_SUCCESS) goto error

#define AIK_PEM_PUB "/opt/xensource/tpm/aik_pem.pub"
#define EK_PEM_PUB "/opt/xensource/tpm/ek_pem.pub"
#define AIK_TCPA_PUB "/opt/xensource/tpm/aik_tcpa.pub"
#define AIK_TPM_BLOB "/opt/xensource/tpm/aiktpmblob"
#ifndef TPMCERTFILE
#define TPMCERTFILE "/opt/xensource/tpm/tpm.cert"
#endif

#define LOG_FILE  "/tmp/xen_tpm_agent.log"

#define BSIZE	128

/* Definitions from section 7 of
 * TCG PC Client Specific Implementation Specification
 * For Conventional BIOS
 */
#define TCG_TAG_PCCLIENT_STORED_CERT		0x1001
#define TCG_TAG_PCCLIENT_FULL_CERT		0x1002
#define TCG_TAG_PCCLIENT_PART_SMALL_CERT	0x1003
#define TCG_FULL_CERT				0
#define TCG_PARTIAL_SMALL_CERT			1



void log_msg(char* file,int line,char *msg, ...);
void exit_status(int status);
int generate_aik();
int read_tpm_ekcert(char*);
int read_tpm_cert();
FILE *log_filp = NULL;

int
main (int ac, char **av)
{
    log_filp = fopen(LOG_FILE,"a+");
    
    if (!log_filp) {
        exit_status(1);
    }
    
    /*Read EK from TPM and write to filr*/
    read_tpm_ek();

    /*Read EK Cert from TPM and write to file */
    read_tpm_ekcert(TPMCERTFILE);
    
    /* Generate AIK for the TPM*/
    generate_aik();

}


int generate_aik() 

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

int read_tpm_ek()
{

    TSS_HCONTEXT	hContext;
    TSS_HTPM    	hTPM;
    TSS_RESULT	    result;
    TSS_HKEY	    hPubek;
    UINT32		    modulusLen;
    UINT32		    e_size;
    BYTE		    *modulus;
    BYTE            *e;
    RSA			    *ekRsa;
    TSS_HPOLICY     ekPolicy;
    FILE            *f_out;
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
                (UINT32)strlen(OWNER_SECRET),(BYTE*)OWNER_SECRET);

        if (result != TSS_SUCCESS) {
            log_msg(__FILE__,__LINE__,"Error Setting TPM Password %s \n", Trspi_Error_String(result));
            exit_status(result);
        } 
        result = Tspi_TPM_GetPubEndorsementKey (hTPM, TRUE, NULL, &hPubek);
    }

    if (result != TSS_SUCCESS) {
            log_msg(__FILE__,__LINE__,"Error Reading TPM EK %s \n", Trspi_Error_String(result));
            log_msg(__FILE__,__LINE__,"Error Reading TPM EK, check the owner password after enabling the TPM \n");
	        exit_status(1);
	}

    result = Tspi_GetAttribData (hPubek, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &modulusLen, &modulus);

    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error TPM EK RSA %s \n", Trspi_Error_String(result));
        return 1;
    }

    if (modulusLen != 256) {
        Tspi_Context_FreeMemory (hContext, modulus);
        log_msg(__FILE__,__LINE__,"Error TPM EK RSA %s \n", Trspi_Error_String(result));
        return 1;
    }

    result = Tspi_GetAttribData(hPubek, TSS_TSPATTRIB_RSAKEY_INFO,
            TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &e_size, &e);

    if (result != TSS_SUCCESS) {
        log_msg(__FILE__,__LINE__,"Error 0x%x on Tspi_Context_GetAttr Exponent\n", result);
        Tspi_Context_FreeMemory (hContext, modulus);
        return 1;
    }

    Tspi_Context_CloseObject (hContext, hPubek);
    ekRsa = RSA_new();
    ekRsa->n = BN_bin2bn (modulus,modulusLen, NULL);
    ekRsa->e = BN_new();
    ekRsa->e = BN_bin2bn(e, e_size, NULL);

    Tspi_Context_FreeMemory (hContext, modulus);
    Tspi_Context_FreeMemory (hContext, e);

    if ((f_out = fopen (EK_PEM_PUB, "wb")) == NULL) {
		log_msg(__FILE__,__LINE__, "Unable to open %s for output\n", EK_PEM_PUB);
		exit_status (1);
	}

    PEM_write_RSA_PUBKEY(f_out, ekRsa);
    fclose(f_out);
    RSA_free(ekRsa);
    log_msg(__FILE__,__LINE__, "EK PEM generated in file %s\n", EK_PEM_PUB);
    return 0;
}

int read_tpm_ekcert(char* certfile)
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
                (UINT32)strlen(OWNER_SECRET),(BYTE*)OWNER_SECRET);
        result = Tspi_Policy_AssignToObject(hNVPolicy, hNV); CKERR;
        blobLen = 5;
        result = Tspi_NV_ReadValue(hNV, 0, &blobLen, &blob);
    }
    
    if (result != TSS_SUCCESS) {
        // printf("Error %s\n",Trspi_Error_String(result));
        log_msg(__FILE__,__LINE__,"Unable to read EK Certificate from TPM\n");
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
    } else if (blob[0] != 0x30)	{ /* Marker of cert structure */
            goto parseerr;
    }

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
        return 1;
    }
    fwrite (ekbuf, 1, ekbufLen, f_out);
    fclose (f_out);
    result = Tspi_Context_CloseObject(hContext, hNV);CKERR;
    result = Tspi_Context_Close(hContext);CKERR;
    return 0;
error:
    log_msg(__FILE__,__LINE__,"Failure, error code: %s\n", Trspi_Error_String(result));
    return 1;
parseerr:
    log_msg(__FILE__,__LINE__,"Failure, unable to parse certificate store structure\n");
    return 2;
}

/* Check the certificate from the key */
/* this in internal function for validatin certs from
 * the public key
 * */
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



