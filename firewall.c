// firewall.c
// Un firewall user-space “all in one” con update/upgrade, log su syslog e dry-run.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#define MAX_LINE   512
#define DEFAULT_CFG "config.conf"

// Prototipi
static void usage(const char *prog);
static int  run_cmd(const char *cmd, int dry_run);
static char *trim(char *s);

int main(int argc, char *argv[]) {
    char *cfg_path = DEFAULT_CFG;
    char *log_path = NULL;
    int   dry_run  = 0;
    int   do_update= 0;
    int   opt;

    // Apri syslog
    openlog("firewall", LOG_PID|LOG_CONS, LOG_USER);
    setlogmask(LOG_UPTO(LOG_INFO));

    while ((opt = getopt(argc, argv, "c:dul:h")) != -1) {
        switch (opt) {
        case 'c': cfg_path  = optarg;           break;
        case 'd': dry_run   = 1;                break;
        case 'u': do_update = 1;                break;
        case 'l': log_path  = optarg;           break;
        case 'h':
        default:
            usage(argv[0]);
        }
    }

    // Se l'utente specifica un log file, aprilo
    FILE *lf = NULL;
    if (log_path) {
        lf = fopen(log_path, dry_run ? "w" : "a");
        if (!lf) {
            syslog(LOG_ERR, "Impossibile aprire logfile '%s': %s", 
                   log_path, strerror(errno));
            // non esco, continuo solo con syslog
        }
    }

    // Verifica permessi di root per apt/nft
    if (geteuid() != 0) {
        syslog(LOG_ERR, "Devi eseguire come root");
        fprintf(stderr, "Errore: esegui come root\n");
        exit(EXIT_FAILURE);
    }

    // 1) update & upgrade se richiesto
    if (do_update) {
        syslog(LOG_INFO, "Avvio apt-get update && upgrade");
        if (run_cmd("apt-get update -y", dry_run) != 0 ||
            run_cmd("apt-get upgrade -y", dry_run) != 0) {
            syslog(LOG_ERR, "apt-get update/upgrade fallito");
            if (lf) fprintf(lf, "apt-get update/upgrade fallito\n");
            // ma proseguiamo comunque
        } else {
            syslog(LOG_INFO, "apt-get update/upgrade completato");
            if (lf) fprintf(lf, "apt-get update/upgrade completato\n");
        }
    }

    // 2) apertura config
    FILE *cf = fopen(cfg_path, "r");
    if (!cf) {
        syslog(LOG_ERR, "Impossibile aprire config '%s': %s", 
               cfg_path, strerror(errno));
        fprintf(stderr, "Errore: non posso aprire %s\n", cfg_path);
        exit(EXIT_FAILURE);
    }
    syslog(LOG_INFO, "Caricata config: %s", cfg_path);
    if (lf) fprintf(lf, "Caricata config: %s\n", cfg_path);

    // 3) esecuzione righe nft
    char line[MAX_LINE];
    int  rc=0, lineno=0;
    while (fgets(line, sizeof(line), cf)) {
        lineno++;
        char *cmd = trim(line);
        if (cmd[0]=='\0' || cmd[0]=='#') continue;

        char full[MAX_LINE + 16];
        snprintf(full, sizeof(full), "nft %s", cmd);

        syslog(LOG_INFO, "[Line %d] %s", lineno, full);
        if (lf) fprintf(lf, "[Line %d] %s\n", lineno, full);

        if (run_cmd(full, dry_run) != 0) {
            syslog(LOG_ERR, "Riga %d Fallita: %s", lineno, full);
            if (lf) fprintf(lf, "Riga %d Fallita\n", lineno);
            rc = EXIT_FAILURE;
        }
    }
    fclose(cf);
    if (lf) fclose(lf);

    syslog(LOG_INFO, "Firewall apply %s", (rc==0?"completato":"con errori"));
    closelog();
    return rc;
}

// Mostra help e esci
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -c FILE   Path to config file (default: %s)\n"
        "  -d        Dry run (stampa i comandi senza eseguirli)\n"
        "  -u        Esegui apt-get update && apt-get upgrade -y\n"
        "  -l FILE   Log su file oltre a syslog\n"
        "  -h        Questo help\n",
        prog, DEFAULT_CFG);
    exit(EXIT_FAILURE);
}

// Esegue o stampa un comando shell
static int run_cmd(const char *cmd, int dry_run) {
    if (dry_run) {
        printf("[DRY] %s\n", cmd);
        return 0;
    }
    int ret = system(cmd);
    if (ret != 0) {
        syslog(LOG_ERR, "Comando fallito (%d): %s", ret, cmd);
    }
    return ret;
}

// Rimuove spazi iniziali/finali
static char *trim(char *s) {
    char *end;
    // left trim
    while (isspace((unsigned char)*s)) s++;
    if (*s == 0) return s;
    // right trim
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return s;
}
