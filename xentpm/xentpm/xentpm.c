
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
                    status = 1;
                    goto clean;
                }
                status = tpm_owned();
                break;
            case 't' : 
                if (argc != 2) {
                    usage();
                    status = 1;
                    goto clean;
                }
                status = take_ownership();
                break;

            case 'e' : 
                if (argc != 2) {
                    usage();
                    status = 1;
                    goto clean;
                }
                status = get_ek();
                break;

            case 'k' : 
                if (argc != 2) {
                    usage();
                    status = 1;
                    goto clean;
                }
                status = get_ekcert();
                break;
            case 'a' : 
                if (argc < 3) {
                    usage();
                    status = 1;
                    goto clean;
                }
                if (argc == 4)
                    status = generate_aik(optarg,argv[optind]);
                else
                    // use a fixed key
                    status = generate_aik(optarg, NULL);
                break;

            case 'p' : 
                if (argc != 3) {
                    usage();
                    status = 1;
                    goto clean;
                }
                status = get_aik_pem(optarg);
                break;

            case 'b' : 
                if (argc != 3) {
                    usage();
                    status = 1;
                    goto clean;
                }
                status = get_aik_tcpa(optarg);
                break;

            case 'c' : 
                if (optind >= argc ) {
                    usage();
                    status = 1;
                    goto clean;
                }   
                //external API call
                if (!argv[optind]) {
                    // TODO return error for invalid args 
                    status = 1;
                   goto clean;
                }
                status = tpm_challenge(optarg,argv[optind]);
                break;
            case 'q' :  
                if (optind >= argc ) {
                    status = 1;
                    usage();
                    goto clean;
                }   
                if (!argv[optind]) {
                    // TODO return error code
                    status = 1;
                   goto clean;
                }
                status = tpm_quote(optarg,argv[optind]);
                break;
            default: 
                usage();
                status = 1;
                break;
        }//switch
    }//while
clean:
    closelog();
    return status;
}    

