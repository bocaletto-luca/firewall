// firewall.c
// Un semplice “firewall” user‐space che esegue comandi nft da config.conf

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#define MAX_LINE 512

void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [-c config_file] [-d]\n"
        "  -c FILE   Path to config file (default: config.conf)\n"
        "  -d        Dry run (stampa i comandi senza eseguirli)\n",
        prog);
    exit(1);
}

int main(int argc, char *argv[]) {
    char *cfg_path = "config.conf";
    int dry_run = 0;
    int opt;

    while ((opt = getopt(argc, argv, "c:dh")) != -1) {
        switch (opt) {
        case 'c':
            cfg_path = optarg;
            break;
        case 'd':
            dry_run = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
        }
    }

    FILE *fp = fopen(cfg_path, "r");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fp)) {
        // Trim inizio/spazi e skip commenti/vuote
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0' || *p == '\n')
            continue;

        // Rimuovi newline finale
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';

        // Componi comando nft
        char cmd[MAX_LINE + 8];
        snprintf(cmd, sizeof(cmd), "nft %s", p);

        if (dry_run) {
            printf("[DRY] %s\n", cmd);
        } else {
            printf("[RUN] %s\n", cmd);
            int ret = system(cmd);
            if (ret != 0) {
                fprintf(stderr, "Error: comando fallito (%s)\n", cmd);
            }
        }
    }

    fclose(fp);
    printf("Firewall apply completed.\n");
    return 0;
}
