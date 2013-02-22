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

int get_ek();
