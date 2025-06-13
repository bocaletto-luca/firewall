// firewall.c
// ––––––––––––––––––––––––––––––––––––––––––––––––––––––––
// Un “all-in-one” che:  
//   • con -u fa apt update & upgrade  
//   • con -d dry-run stampa i comandi  
//   • altrimenti carica config.conf ed esegue i comandi nft

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#define MAX_LINE 512

void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [-c config_file] [-d] [-u]\n"
        "  -c FILE   Path to config file (default: config.conf)\n"
        "  -d        Dry run (stampa i comandi senza eseguirli)\n"
        "  -u        Esegui apt-get update && apt-get upgrade -y\n",
        prog);
    exit(1);
}

// Esegue (o stampa, in dry-run) un comando di shell
int exec_cmd(const char *cmd, int dry_run) {
    if (dry_run) {
        printf("[DRY] %s\n", cmd);
        return 0;
    } else {
        printf("[RUN] %s\n", cmd);
        return system(cmd);
    }
}

int main(int argc, char *argv[]) {
    char *cfg_path = "config.conf";
    int dry_run = 0, do_update = 0;
    int opt;

    while ((opt = getopt(argc, argv, "c:duh")) != -1) {
        switch (opt) {
        case 'c': cfg_path = optarg;        break;
        case 'd': dry_run = 1;              break;
        case 'u': do_update = 1;            break;
        case 'h':
        default:  usage(argv[0]);
        }
    }

    // 1) Se richiesto, apt-get update & upgrade -y
    if (do_update) {
        exec_cmd("sudo apt-get update", dry_run);
        exec_cmd("sudo apt-get upgrade -y", dry_run);
        // Se volevi fermarti qui, decommenta exit:
        // return 0;
    }

    // 2) Leggi config e applica regole nft
    FILE *fp = fopen(cfg_path, "r");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0' || *p == '\n')
            continue;
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';

        char cmd[MAX_LINE + 8];
        snprintf(cmd, sizeof(cmd), "sudo nft %s", p);
        if (exec_cmd(cmd, dry_run) != 0) {
            fprintf(stderr, "Errore comando: %s\n", cmd);
        }
    }
    fclose(fp);

    printf("Firewall apply completed.\n");
    return 0;
}
