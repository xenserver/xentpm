
#include "xentpm.h"
#include <getopt.h>

void
usage()
{
    printf("usage: xentpm\n");
    printf("           --tpm_owned |\n");
    printf("           --take_ownership |\n");
    printf("           --get_ekey |\n");
    printf("           --get_ekcert |\n");
    printf("           --gen_aik <aikblobpath> <xenpubkey>  \n");
    printf("           --get_aik_pem <aikblobpath>\n");
    printf("           --get_aik_tcpa <aikblobpath>\n");
    printf("           --tpm_challenge <aikblobpath> <challenge>\n");
    printf("           --tpm_quote <nonce> <aikblobpath>\n");
}

#define MAX_ARG_SIZE 1024

int main(int argc, char *argv[]) 
{
    int opt= 0;
    int status = 0;
   
    openlog("xentpm", LOG_PID, LOG_USER);
    static struct option long_options[] = {
        {"tpm_owned",      no_argument, 0, 'o' },
        {"take_ownership", no_argument, 0, 't' },
        {"get_ekey",       no_argument, 0, 'e' },
        {"get_ekcert",     no_argument, 0, 'k' },
        {"gen_aik",        required_argument, 0, 'a' },
        {"get_aik_pem",    required_argument, 0, 'p' },
        {"get_aik_tcpa",   required_argument, 0, 'b' },
        {"tpm_challenge",  required_argument, 0, 'c' },
        {"tpm_quote",      required_argument, 0, 'q' },
        {0, 0, 0, 0 }
    };

    int long_index =0;
    while ((opt = getopt_long(argc, argv,"otek:a:p:b:c:q", 
                    long_options, &long_index )) != -1) {
        switch (opt) {
            case 'o' :
                if (argc != 2) {
                    usage();
                    status = TSS_E_BAD_PARAMETER;
                    goto clean;
                }
                status = tpm_owned();
                break;
            case 't' : 
                if (argc != 2) {
                    usage();
                    status = TSS_E_BAD_PARAMETER;
                    goto clean;
                }
                status = take_ownership();
                break;

            case 'e' : 
                if (argc != 2) {
                    usage();
                    status = TSS_E_BAD_PARAMETER;
                    goto clean;
                }
                status = get_endorsment_key();
                break;

            case 'k' : 
                if (argc != 2) {
                    usage();
                    status = TSS_E_BAD_PARAMETER;
                    goto clean;
                }
                status = get_endorsment_keycert();
                break;
            case 'a' : 
                if (argc != 4) {
                    usage();
                    status = TSS_E_BAD_PARAMETER;
                    goto clean;
                }
                    status = generate_aik(optarg,argv[optind]);
                break;

            case 'p' : 
                if (argc != 3) {
                    usage();
                    goto clean;
                }
                status = get_aik_pem(optarg);
                break;

            case 'b' : 
                if (argc != 3) {
                    usage();
                    status = TSS_E_BAD_PARAMETER;
                    goto clean;
                }
                status = get_aik_tcpa(optarg);
                break;

            case 'c' : 
                if (optind >= argc ) {
                    usage();
                    status = TSS_E_BAD_PARAMETER;
                    goto clean;
                }   
                //external API call
                if (!argv[optind]) {
                    status = TSS_E_BAD_PARAMETER;
                    goto clean;
                }
                status = tpm_challenge(optarg,argv[optind]);
                break;
            case 'q' :  
                if (optind >= argc ) {
                    status = TSS_E_BAD_PARAMETER;
                    usage();
                    goto clean;
                }   
                if (!argv[optind]) {
                    status = TSS_E_BAD_PARAMETER;
                    goto clean;
                }
                status = tpm_quote(optarg,argv[optind]);
                break;
            default: 
                usage();
                status = TSS_E_BAD_PARAMETER;
                break;
        }//switch
    }//while
clean:
    closelog();

    //
    // Shell return codes only go up to 255, but trouser error codes can be much larger than that.
    // so send the real error code out on stderr and return 1 in the case of an error.  The python
    // xapi plugin wrapper will do the right thing.
    if (!status) {
        return 0;
    } else {
        fprintf(stderr, "%d", status);
        return 1;
    }
}    

