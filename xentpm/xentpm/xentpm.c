#ifndef XENTPM_H_
#define XENTPM_H_

#include "xentpm.h"

FILE *log_filp = NULL;

void
Usage()
{
    printf("Usage: xentpm\n");
    printf("           --tpm_owned |\n");
    printf("           --take_ownership |\n");
    printf("           --get_ekey |\n");
    printf("           --get_ekcert |\n");
    printf("           --gen_aik <aikblobfile>\n");
    printf("           --get_aik_pem <aikblobfile>\n");
    printf("           --get_aik_tcpa <aikblobfile>\n");
    printf("           --tpm_challenge <aikblobfile> <challenge>\n");
    printf("           --tpm_quote <nonce> <aikblobfile>\n");
}

int
main(int argc, char **argv)
{
    log_filp = fopen(LOG_FILE,"a+");
    
    if (!log_filp) {
        exit_status(1);
    }

    if (argc < 2) {
        Usage();
        exit_status(1);
    }

    if (!strcasecmp(argv[1], "--tpm_owned")) {
        return tpm_owned();
    } else if (!strcasecmp(argv[1], "--take_ownership")) {
        return take_ownership();
    } else if (!strcasecmp(argv[1], "--get_ekey")) {
        return get_ek();
    } else if (!strcasecmp(argv[1], "--get_ekcert")) {
        return get_ekcert();
    } else if (!strcasecmp(argv[1], "--gen_aik")) {
        if (argc < 3) {
            Usage();
            exit_status(1);
        }
        return generate_aik(argv[2]);
    } else if (!strcasecmp(argv[1], "--get_aik_pem")) {
        if (argc < 3) {
            Usage();
            exit_status(1);
        }
        return get_aik_pem(argv[2]);
    } else if (!strcasecmp(argv[1], "--get_aik_tcpa")) {
        if (argc < 3) {
            Usage();
            exit_status(1);
        }
        return get_aik_tcpa(argv[2]);
    } else if (!strcasecmp(argv[1], "--tpm_challenge")) {
        if (argc < 4) {
            Usage();
            exit_status(1);
        }
        return tpm_challenge(argv[2], argv[3]);
    } else if (!strcasecmp(argv[1], "--tpm_quote")) {
        if (argc < 4) {
            Usage();
            exit_status(1);
        }
        return tpm_quote(argv[2], argv[3]);
    } else {
        printf("Unknown option %s\n", argv[1]);
        Usage();
        exit_status(1);
    }
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

#endif //XENTPM_H_
