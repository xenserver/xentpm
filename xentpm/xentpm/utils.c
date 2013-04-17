#include "xentpm.h"
#include <unistd.h>
#include <string.h>
#include <ctype.h>


static int get_key_bytes(unsigned char * md, unsigned char * buf);
static char get_val(char c);

int print_base64(void* data, UINT32 len)
{

    BIO *bmem, *b64;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, data, len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    char *b64Buff = (char*)malloc(bptr->length);
    
    if (!b64Buff) {
        syslog(LOG_ERR, "Error in memory allocation %s and %d ",__FILE__,__LINE__);
        return 1;
    } 
    memcpy(b64Buff, bptr->data, bptr->length-1);
    b64Buff[bptr->length-1] = 0;
    BIO_free_all(b64);
    printf(b64Buff);
    free(b64Buff);
    return 0;
}

int read_tpm_key(unsigned char *key, int keyLen)
{
    FILE* fp;
    unsigned char key_buf[80];
    memset(key_buf,0,80);
    if ((fp = fopen (KEY_FILE, "rb")) == NULL) {
        syslog(LOG_ERR, "Unable to open %s for reading\n", KEY_FILE);
        return 1;
    }
    
    if (fread(key_buf, 1,80, fp) < KEY_HEX_SIZE) {
        syslog(LOG_INFO, "Expecting SHA1 HMAC in  %s\n", KEY_FILE);
    }
    if (get_key_bytes(key,key_buf))  {
        syslog(LOG_ERR, "Error readin key from %s\n", KEY_FILE);
        return 1;
    }

    fclose(fp);

    return 0;
}


static int get_key_bytes(unsigned char * md, unsigned char * buf)
{
    int i;
    char t1;
    char t2;
    for (i = 0; i < KEY_SIZE; i++) {
        t1 = get_val(buf[i*2]);    
        t2 = get_val(buf[i*2+1]);
        if( t1 < 0 || t2 < 0) {
            return 1;  
        }
        md[i] = (t1 << 4) + t2; 
    }
    return 0;
}

static char get_val(char c) 
{
    char result;
    if (isdigit(c))
        result = c-'0';
    else if (isupper(c))
        result = c-'A' + 10;
    else if (islower(c))
        result = c-'a' + 10;
    else
        return -1;
    return result;
}

