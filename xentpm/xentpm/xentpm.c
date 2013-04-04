
#include "xentpm.h"

void
usage()
{
    printf("usage: xentpm\n");
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
    int status = 0;
    openlog("xentpm", LOG_PID, LOG_USER);

    if (argc < 2) {
        usage();
        status = 1;
        goto clean;
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
            usage();
            status = 1;
            goto clean;
        }
        return generate_aik(argv[2]);
    } else if (!strcasecmp(argv[1], "--get_aik_pem")) {
        if (argc < 3) {
            usage();
            status = 1;
            goto clean;
        }
        return get_aik_pem(argv[2]);
    } else if (!strcasecmp(argv[1], "--get_aik_tcpa")) {
        if (argc < 3) {
            usage();
            status = 1;
            goto clean;
        }
        return get_aik_tcpa(argv[2]);
    } else if (!strcasecmp(argv[1], "--tpm_challenge")) {
        if (argc < 4) {
            usage();
            status = 1;
            goto clean;
        }
        return tpm_challenge(argv[2], argv[3]);
    } else if (!strcasecmp(argv[1], "--tpm_quote")) {
        if (argc < 4) {
            usage();
            status = 1;
            goto clean;
        }
        return tpm_quote(argv[2], argv[3]);
    } else {
        printf("Unknown option %s\n", argv[1]);
        usage();
        status = 1;
        goto clean;
    }

clean:
    closelog();
    return status;
}

