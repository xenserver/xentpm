/*
 * Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * *   Redistributions of source code must retain the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <getopt.h>
#include "xentpm.h"

void usage()
{
    printf("usage: xentpm\n");
    printf("           --is_tpm_owned\n");
    printf("           --take_ownership\n");
    printf("           --get_ekey\n");
    printf("           --get_ekcert\n");
    printf("           --gen_aik <xencert_base64>\n");
    printf("           --get_aik_pem \n");
    printf("           --get_aik_tcpa \n");
    printf("           --tpm_challenge <challenge>\n");
    printf("           --tpm_quote <nonce> \n");
}

int main(int argc, char *argv[]) 
{
    int opt = 0;
    int status = TSS_E_BAD_PARAMETER;
    int long_index = 0;
   
    openlog("xentpm", LOG_PID, LOG_USER);
    
    static struct option long_options[] = {
        {"is_tpm_owned",   no_argument, 0, 'o' },
        {"take_ownership", no_argument, 0, 't' },
        {"get_ekey",       no_argument, 0, 'e' },
        {"get_ekcert",     no_argument, 0, 'k' },
        {"gen_aik",        required_argument, 0, 'a' },
        {"get_aik_pem",    no_argument, 0, 'p' },
        {"get_aik_tcpa",   no_argument, 0, 'b' },
        {"tpm_challenge",  required_argument, 0, 'c' },
        {"tpm_quote",      required_argument, 0, 'q' },
        {0, 0, 0, 0 }
    };
    if( argc < 2 ){
        usage();
        goto clean;
    }

    while ((opt = getopt_long(argc, argv,"otek:a:p:b:c:q:", 
                    long_options, &long_index)) != -1) {
        switch (opt) {
            case 'o' :
                if (argc != 2) {
                    usage();
                    goto clean;
                }
                status = tpm_owned();
                break;
            case 't' : 
                if (argc != 2) {
                    usage();
                    goto clean;
                }
                status = take_ownership();
                break;

            case 'e' : 
                if (argc != 2) {
                    usage();
                    goto clean;
                }
                status = get_endorsment_key();
                break;

            case 'k' : 
                if (argc != 2) {
                    usage();
                    goto clean;
                }
                status = get_endorsment_keycert();
                break;
            case 'a' : 
                if (argc != 3) {
                    usage();
                    goto clean;
                }
                status = generate_aik(optarg);
                break;

            case 'p' : 
                if (argc != 2) {
                    usage();
                    goto clean;
                }
                status = get_aik_pem();
                break;

            case 'b' : 
                if (argc != 2) {
                    usage();
                    goto clean;
                }
                status = get_aik_tcpa();
                break;

            case 'c' : 
                
                if (argc != 3) {
                    usage();
                    goto clean;
                }
                
                status = tpm_challenge(optarg);
                break;
            case 'q' :  
                
                if (argc != 3) {
                    usage();
                    goto clean;
                }
                
                status = tpm_quote(optarg);
                break;
            default: 
                usage();
                break;
        }//switch
    }//while
clean:
    closelog();

    /*
     * Shell return codes only go up to 255, but trouser error codes can be much larger than that.
     * so send the real error code out on stderr and return 1 in the case of an error.  The python
     * xapi plugin wrapper will do the right thing.
    */
    if (!status) {
        return 0;
    } else {
        fprintf(stderr, "%d", status);
        return 1;
    }
}    

