#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <errno.h>
#include <syslog.h>
#include <trousers/tss.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <trousers/trousers.h>

#define OWNER_SECRET    "xenroot"

