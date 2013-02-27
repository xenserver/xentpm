/*
 * aikrespond.c
 *
 * Third step in proving an AIK is valid without using a Privacy CA.
 *
 * Reads AIK blob file and challenge file from challenger. Decrypts
 * encrypted data and outputs to a file, which should be sent back to
 * challenger. Successful decryption proves that it is a real AIK.
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

#include "xentpm.h"

int tpm_challenge(char *aik_blob_file, char *challenge_file, char *response_file)
{
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_HKEY hAIK;
    TSS_HPOLICY	hTPMPolicy;
    TSS_HPOLICY	hSrkPolicy;
    TSS_HPOLICY	hAIKPolicy;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    BYTE srkSecret[] = TSS_WELL_KNOWN_SECRET;
    FILE *f_in;
    FILE *f_out;
    BYTE *response;
    UINT32 responseLen;
    BYTE *buf;
    UINT32 bufLen;
    BYTE *asym;
    UINT32 asymLen;
    BYTE *sym;
    UINT32 symLen;
    int	i;
    int	result;

    log_msg(__FILE__,__LINE__, "Recieved a Challange\n");

    result = take_ownership();
    if (result) {
        log_msg(__FILE__,__LINE__,"Error 0x%X taking ownership of TPM.\n", result);
        exit_status(result);
    }

    result = Tspi_Context_Create(&hContext); CKERR;
    result = Tspi_Context_Connect(hContext, NULL); CKERR;
    result = Tspi_Context_LoadKeyByUUID(hContext,
                TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK); CKERR;
    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy); CKERR;
    result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_PLAIN,
                strlen(OWNER_SECRET), OWNER_SECRET); CKERR;
    result = Tspi_Context_GetTpmObject(hContext, &hTPM); CKERR;
    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
                TSS_POLICY_USAGE, &hTPMPolicy); CKERR;
    result = Tspi_Policy_AssignToObject(hTPMPolicy, hTPM);
    result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN,
                strlen(OWNER_SECRET), OWNER_SECRET); CKERR;

    // Read AIK blob
    if ((f_in = fopen(aik_blob_file, "rb")) == NULL) {
        log_msg(__FILE__,__LINE__, "Unable to open file %s\n", aik_blob_file);
        exit(1);
    }
    fseek(f_in, 0, SEEK_END);
    bufLen = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);
    buf = malloc(bufLen);
    if (fread(buf, 1, bufLen, f_in) != bufLen) {
        log_msg(__FILE__,__LINE__, "Unable to readn file %s\n", aik_blob_file);
        exit(1);
    }
    fclose(f_in);

    result = Tspi_Context_LoadKeyByBlob(hContext, hSRK, bufLen, buf, &hAIK); CKERR;
    free(buf);

    // Read challenge file
    if ((f_in = fopen(challenge_file, "rb")) == NULL) {
        log_msg(__FILE__,__LINE__, "Unable to open file %s\n", challenge_file);
        exit(1);
    }
    fseek(f_in, 0, SEEK_END);
    bufLen = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);
    buf = malloc(bufLen);
    if (fread(buf, 1, bufLen, f_in) != bufLen) {
        log_msg(__FILE__,__LINE__, "Unable to readn file %s\n", challenge_file);
        exit(1);
    }
    fclose(f_in);

    // Parse challenge
    if (bufLen < 8)
        goto badchal;
    asymLen = ntohl(*(UINT32*)buf);
    asym = buf + 4;
    buf += asymLen + 4;
    if (bufLen < asymLen+8)
        goto badchal;
    symLen = ntohl(*(UINT32*)buf);
    if (bufLen != asymLen + symLen + 8)
        goto badchal;
    sym = buf + 4;

    // Decrypt challenge data
    result = Tspi_TPM_ActivateIdentity(hTPM, hAIK, asymLen, asym,
                                       symLen, sym,
                                       &responseLen, &response); CKERR;

    // Output response file
    if ((f_out = fopen (response_file, "w")) == NULL) {
        log_msg(__FILE__,__LINE__, "Unable to create file %s\n", response_file);
        exit(1);
    }
    if (fwrite(response, 1, responseLen, f_out) != responseLen) {
        log_msg(__FILE__,__LINE__, "Unable to write to file %s\n", response_file);
        exit(1);
    }
    fclose(f_out);

    log_msg(__FILE__,__LINE__,"Success in response!\n");
    return 0;

error:
    log_msg(__FILE__,__LINE__, "Failure, error code: 0x%x %s\n", result,Trspi_Error_String(result));
    return 1;

badchal:
    log_msg(__FILE__,__LINE__, "Challenge file format is wrong\n");
    return 1;
}
