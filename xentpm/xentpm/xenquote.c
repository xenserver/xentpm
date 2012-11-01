/*
 * xenquote.c
 *
 * Produce a PCR quote using an AIK.
 *
 * All available PCR's are masked
 * Nonce is fixed at 0 for now.
 *
 * The format of the quote file output is as follows:
 * 2 bytes of PCR bitmask length (big-endian)
 * PCR bitmask (LSB of 1st byte is PCR0, MSB is PCR7; LSB of 2nd byte is PCR8, etc)
 * 4 bytes of PCR value length (20 times number of PCRs) (big-endian)
 * PCR values
 * 256 bytes of Quote signature
 *
 * Note that the 1st portion is the serialized TPM_PCR_SELECTION that gets hashed.
 *
 * Takes an optional challenge file to be hashed as the externalData input
 * to the Quote. This would typically be supplied by the challenger to prevent
 * replay of old Quote output. If no file is specified the challenge is zeros.
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
#include <arpa/inet.h>
#include <time.h>
#include <stdarg.h>
#define TPMPASSWD "xenroot"

#define CKERR	if (result != TSS_SUCCESS) goto error

#define LOG_FILE  "/tmp/xen_tpm_agent.log"

void log_msg(char* file,int line,char *msg, ...);
void exit_status(int status);
FILE *log_filp = NULL;


static void sha1(TSS_HCONTEXT hContext, void *buf, UINT32 bufLen, BYTE *digest);

int
main (int ac, char **av)
{
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_HKEY	hSRK;
	TSS_HKEY	hAIK;
	TSS_HPOLICY	hSrkPolicy;
	TSS_HPOLICY	hAIKPolicy;
	TSS_HPCRS	hPCRs;
	TSS_UUID	SRK_UUID = TSS_UUID_SRK;
	TSS_VALIDATION	valid;
	TPM_QUOTE_INFO	*quoteInfo;
	FILE		*f_in;
	FILE		*f_out;
	char		*chalfile = NULL;
	char		*pass = NULL;
	UINT32		tpmProp;
	UINT32		npcrMax;
	UINT32		npcrBytes;
	UINT32		npcrs = 0;
	BYTE		*buf;
	UINT32		bufLen;
	BYTE		*bp;
	BYTE		*tmpbuf;
	UINT32		tmpbufLen;
	BYTE		chalmd[20];
	BYTE		pcrmd[20];
	int		i;
	int		result;

     log_filp = fopen(LOG_FILE,"a+");
    
     if (!log_filp) {
        exit_status(1);
     }
    
	log_msg (__FILE__, __LINE__," Request for Quote Generation!\n");

	while (ac > 3) {
		if (0 == strcmp(av[1], "-c")) {
			chalfile = av[2];
			for (i=3; i<ac; i++)
				av[i-2] = av[i];
			ac -= 2;
		} else
			break;
	}

	if (ac < 2) {
		log_msg (__FILE__,__LINE__,"Usage: %s [-c challengefile] aikblobfile outquotefile\n", av[0]);
		exit (1);
	}

	result = Tspi_Context_Create(&hContext); CKERR;
	result = Tspi_Context_Connect(hContext, NULL); CKERR;
	result = Tspi_Context_LoadKeyByUUID(hContext,
			TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK); CKERR;
	result = Tspi_GetPolicyObject (hSRK, TSS_POLICY_USAGE, &hSrkPolicy); CKERR;
	result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_PLAIN,
			 strlen(TPMPASSWD), (BYTE*)TPMPASSWD); CKERR;
	result = Tspi_Context_GetTpmObject (hContext, &hTPM); CKERR;

	/* Hash challenge file if present */
	if (chalfile) {
		if ((f_in = fopen(chalfile, "rb")) == NULL) {
			log_msg (__FILE__,__LINE__,"Unable to open file %s\n", chalfile);
			exit (1);
		}
		fseek (f_in, 0, SEEK_END);
		bufLen = ftell (f_in);
		fseek (f_in, 0, SEEK_SET);
		buf = malloc (bufLen);
		if (fread(buf, 1, bufLen, f_in) != bufLen) {
			log_msg (__FILE__,__LINE__,"Unable to readn file %s\n", chalfile);
			exit (1);
		}
		fclose (f_in);
		sha1 (hContext, buf, bufLen, chalmd);
		free (buf);
	} else {
		memset (chalmd, 0, sizeof(chalmd));
	}

	/* Read AIK blob */
	if ((f_in = fopen(av[1], "rb")) == NULL) {
		log_msg (__FILE__,__LINE__,"Unable to open file %s\n", av[1]);
		exit (1);
	}
	fseek (f_in, 0, SEEK_END);
	bufLen = ftell (f_in);
	fseek (f_in, 0, SEEK_SET);
	buf = malloc (bufLen);
	if (fread(buf, 1, bufLen, f_in) != bufLen) {
		log_msg (__FILE__,__LINE__,"Unable to readn file %s\n", av[1]);
		exit (1);
	}
	fclose (f_in);
    
	result = Tspi_Context_LoadKeyByBlob (hContext, hSRK, bufLen, buf, &hAIK); CKERR;
	free (buf);
    
    /*password for AIK*/
	if (pass) {
		result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
				TSS_POLICY_USAGE, &hAIKPolicy); CKERR;
		result = Tspi_Policy_AssignToObject(hAIKPolicy, hAIK);
		result = Tspi_Policy_SetSecret (hAIKPolicy, TSS_SECRET_MODE_PLAIN,
				strlen(pass)+1, (BYTE*)pass); CKERR;
	}

	/* Create PCR list to be quoted */
    /*We will quote all the PCR's */
	
    tpmProp = TSS_TPMCAP_PROP_PCR;
	result = Tspi_TPM_GetCapability(hTPM, TSS_TPMCAP_PROPERTY,
		sizeof(tpmProp), (BYTE *)&tpmProp, &tmpbufLen, &tmpbuf); CKERR;
	npcrMax = *(UINT32 *)tmpbuf;
	Tspi_Context_FreeMemory(hContext, tmpbuf);
	npcrBytes = (npcrMax + 7) / 8; // PCR MASK
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS,
		TSS_PCRS_STRUCT_INFO, &hPCRs); CKERR;
	
	/* Also PCR buffer */
	buf = malloc (2 + npcrBytes + 4 + 20 * npcrMax);
	*(UINT16 *)buf = htons(npcrBytes);
	for (i=0; i<npcrBytes; i++)
		buf[2+i] = 0;

	for (i=0; i<npcrMax; i++) {
		long pcr = i ;
		result = Tspi_PcrComposite_SelectPcrIndex(hPCRs, pcr); CKERR;
		++npcrs;
		buf[2+(pcr/8)] |= 1 << (pcr%8);
	}

	/* Create TSS_VALIDATION struct for Quote */
	valid.ulExternalDataLength = sizeof(chalmd);
	valid.rgbExternalData = chalmd;

	/* Perform Quote */
	result = Tspi_TPM_Quote(hTPM, hAIK, hPCRs, &valid); CKERR;
	quoteInfo = (TPM_QUOTE_INFO *)valid.rgbData;

	/* Fill in the PCR buffer */
	bp = buf + 2 + npcrBytes;
	*(UINT32 *)bp = htonl (20*npcrs);
	bp += sizeof(UINT32);
	for (i=0; i<=npcrMax; i++) {
		if (buf[2+(i/8)] & (1 << (i%8))) {
			result = Tspi_PcrComposite_GetPcrValue(hPCRs,
				i, &tmpbufLen, &tmpbuf); CKERR;
			memcpy (bp, tmpbuf, tmpbufLen);
			bp += tmpbufLen;
			Tspi_Context_FreeMemory(hContext, tmpbuf);
		}
	}
	bufLen = bp - buf;

	/* Test the hash */
	sha1 (hContext, buf, bufLen, pcrmd);
	if (memcmp (pcrmd, quoteInfo->compositeHash.digest, sizeof(pcrmd)) != 0) {
		/* Try with smaller digest length */
		*(UINT16 *)buf = htons(npcrBytes-1);
		memmove (buf+2+npcrBytes-1, buf+2+npcrBytes, bufLen-2-npcrBytes);
		bufLen -= 1;
		sha1 (hContext, buf, bufLen, pcrmd);
		if (memcmp (pcrmd, quoteInfo->compositeHash.digest, sizeof(pcrmd)) != 0) {
			log_msg (__FILE__,__LINE__,"Inconsistent PCR hash in output of quote\n");
			exit (1);
		}
	}
	Tspi_Context_FreeMemory(hContext, tmpbuf);

	/* Create quote file */
    /* content of the quote file is following
     * following data is serilized in this order
     * 1)uit16 PCRSelectMAskSize 
     * 2)BYTE* PCRSelectMast
     * 3)uint32 QuoteSize 
     * 4)BYTE *Quote (PCR Quote readable in Text)
     * 5)BYTE *Signature
     *
     * The TPM/Trousers generate The composite hash of fields 1- 4
     * this is used to fill TPM_Quote strcutre for verifying quote
     * the Signature is of TPM_Quote from the TPM 
     * For quote verification read details below.
     * */
	
    if ((f_out = fopen (av[ac-1], "wb")) == NULL) {
		log_msg (__FILE__,__LINE__,"Unable to create file %s\n", av[ac-1]);
		exit (1);
	}
	if (fwrite (buf, 1, bufLen, f_out) != bufLen) {
		log_msg (__FILE__,__LINE__,"Unable to write to file %s\n", av[ac-1]);
		exit (1);
	}
	if (fwrite (valid.rgbValidationData, 1, valid.ulValidationDataLength, f_out)
			!= valid.ulValidationDataLength) {
		log_msg (__FILE__,__LINE__,"Unable to write to file %s\n", av[ac-1]);
		exit (1);
	}
	fclose (f_out);

	log_msg (__FILE__, __LINE__," Generate Quote Success!\n");
	return 0;

error:
	log_msg (__FILE__,__LINE__,"Failure, error code: 0x%x\n", result);
	return 1;
}

static void
sha1(TSS_HCONTEXT hContext, void *buf, UINT32 bufLen, BYTE *digest)
{
	TSS_HHASH	hHash;
	BYTE		*tmpbuf;
	UINT32		tmpbufLen;

	Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH,
		TSS_HASH_DEFAULT, &hHash);
	Tspi_Hash_UpdateHashValue(hHash, bufLen, (BYTE *)buf);
	Tspi_Hash_GetHashValue(hHash, &tmpbufLen, &tmpbuf);
	memcpy (digest, tmpbuf, tmpbufLen);
	Tspi_Context_FreeMemory(hContext, tmpbuf);
	Tspi_Context_CloseObject(hContext, hHash);
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


