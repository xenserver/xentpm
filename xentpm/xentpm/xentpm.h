#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <errno.h>
#include <trousers/tss.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <trousers/trousers.h>

#define OWNER_SECRET    "xenroot"

#define LOG_FILE  "/tmp/xen_tpm_agent.log"

void log_msg(char* file,int line,char *msg, ...);
void exit_status(int status);

extern FILE *log_filp;

#define CKERR if (result != TSS_SUCCESS) { log_msg(__FILE__,__LINE__,"Failure, error code: 0x%x %s \n", result,Trspi_Error_String(result)); return 1; }

