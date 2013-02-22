#ifndef XENTPM_H_
#define XENTPM_H_

#include "xentpm.h"
#include <getopt.h>

FILE *log_filp = NULL;

int
main (int argc, char **argv)
{
    log_filp = fopen(LOG_FILE,"a+");
    
    if (!log_filp) {
        exit_status(1);
    }

    static struct option long_options[] =
    {
        { "tpm_owned", no_argument, 0, 0 },
        { "take_ownership", no_argument, 0, 0 },
        { "get_ekey", no_argument, 0, 0 },
        { "get_ekcert", no_argument, 0, 0 },
        { 0, 0, 0, 0 }
    };

    int option_index = 0;
    int c = getopt_long(argc, argv, "01", long_options, &option_index);
    switch (c) {
        case 0:
            switch (option_index) {
                case 0:
                    return tpm_owned();
                    break;

                case 1:
                    return take_ownership();
                    break;

                case 2:
                    return get_ek();
                    break;

                case 3:
                    return get_ekcert();
                    break;
            }
            break;

        default:
            if (argc > 1) {
                printf("Unknown option %s\n", argv[1]);
            }
            printf("Usage: xentpm --get_ekey | --get_ekcert\n"); 
            break;
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
