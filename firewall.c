// firewall.c
// ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
// Un firewall user-space avanzato in C with:
//  • check nft version
//  • backup/restore ruleset
//  • daemonize + pidfile
//  • hot-reload via inotify + SIGHUP
//  • execvp() diretto
//  • logging su syslog + file
//  • dry-run, update/upgrade, config path

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>
#include <sys/inotify.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>

#define MAX_LINE    512
#define EVENT_SIZE  (sizeof(struct inotify_event))
#define BUF_LEN     (1024 * (EVENT_SIZE + 16))
#define MIN_NFT_VER "0.9.0"
#define DEFAULT_CFG "config.conf"
#define PID_FILE    "/var/run/fwctl.pid"
#define BACKUP_FILE "/var/lib/fwctl/ruleset.bak"

// Global state
static int  dry_run   = 0;
static int  do_update = 0;
static char *cfg_path = DEFAULT_CFG;
static FILE *lf       = NULL;
static volatile sig_atomic_t reload_cfg = 0;
static volatile sig_atomic_t terminate  = 0;

// Prototypes
static void usage(const char *prog);
static void daemonize(const char *pidfile);
static void handle_signal(int sig);
static int  check_nft(void);
static int  run_cmd(char *const argv[]);
static char *trim(char *s);
static void backup_ruleset(void);
static void restore_ruleset(void);
static void apply_config(void);
static void watch_config(void);

int main(int argc, char *argv[]) {
    int opt;
    openlog("fwctl", LOG_PID|LOG_CONS, LOG_DAEMON);
    setlogmask(LOG_UPTO(LOG_INFO));

    while ((opt = getopt(argc, argv, "c:dul:h")) != -1) {
        switch (opt) {
        case 'c': cfg_path  = optarg;       break;
        case 'd': dry_run   = 1;            break;
        case 'u': do_update = 1;            break;
        case 'l':
            lf = fopen(optarg, dry_run ? "w" : "a");
            if (!lf) syslog(LOG_ERR, "open log %s: %s", optarg, strerror(errno));
            break;
        case 'h':
        default: usage(argv[0]);
        }
    }

    // root check
    if (geteuid()!=0) {
        fprintf(stderr,"Errore: serve root\n");
        exit(EXIT_FAILURE);
    }

    // nft version
    if (check_nft() != 0) exit(EXIT_FAILURE);

    // optional daemon
    daemonize(PID_FILE);

    // signals
    signal(SIGHUP, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGINT,  handle_signal);

    // optional update/upgrade
    if (do_update) {
        char *upd[] = { "apt-get","update","-y",NULL };
        char *upg[] = { "apt-get","upgrade","-y",NULL };
        syslog(LOG_INFO, "Running apt-get update");
        if (run_cmd(upd)!=0) syslog(LOG_ERR,"apt-get update failed");
        syslog(LOG_INFO, "Running apt-get upgrade");
        if (run_cmd(upg)!=0) syslog(LOG_ERR,"apt-get upgrade failed");
    }

    // backup current ruleset
    backup_ruleset();

    // initial apply
    apply_config();

    // watch + reload loop
    watch_config();

    // restore original on exit
    restore_ruleset();

    syslog(LOG_INFO,"Firewall terminated");
    closelog();
    if (lf) fclose(lf);
    return 0;
}

// Print usage & exit
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        " -c FILE   config file (default: %s)\n"
        " -d        dry-run\n"
        " -u        apt-get update/upgrade\n"
        " -l FILE   additional logfile\n"
        " -h        help\n",
        prog, DEFAULT_CFG);
    exit(EXIT_FAILURE);
}

// Double-fork daemon + pidfile
static void daemonize(const char *pidfile) {
    pid_t pid = fork();
    if (pid<0) exit(EXIT_FAILURE);
    if (pid>0) exit(EXIT_SUCCESS);
    if (setsid() < 0) exit(EXIT_FAILURE);
    if (fork()>0) exit(EXIT_SUCCESS);
    umask(0);
    chdir("/");
    close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);

    // PID file
    int fd = open(pidfile,O_RDWR|O_CREAT,0640);
    if (fd<0) { syslog(LOG_ERR,"pidfile open: %s",strerror(errno)); return; }
    char buf[32]; snprintf(buf,sizeof(buf),"%d\n",getpid());
    write(fd, buf, strlen(buf)); close(fd);
}

// Handle SIGHUP (reload) and SIGTERM (exit)
static void handle_signal(int sig) {
    if (sig==SIGHUP)   reload_cfg = 1;
    if (sig==SIGTERM || sig==SIGINT) terminate = 1;
}

// Ensure `nft --version` >= MIN_NFT_VER
static int check_nft(void) {
    int pipefd[2];
    if (pipe(pipefd)!=0) return -1;
    if (fork()==0) {
        dup2(pipefd[1],1); close(pipefd[0]); close(pipefd[1]);
        execlp("nft","nft","--version",NULL);
        _exit(1);
    }
    close(pipefd[1]);
    char buf[64]; read(pipefd[0],buf,sizeof(buf)); close(pipefd[0]);
    if (strstr(buf,MIN_NFT_VER)==NULL) {
        syslog(LOG_ERR,"nft version < %s: %s",MIN_NFT_VER,buf);
        return -1;
    }
    syslog(LOG_INFO,"nft version OK: %s",buf);
    return 0;
}

// Execvp wrapper
static int run_cmd(char *const argv[]) {
    if (dry_run) {
        fprintf(stdout,"[DRY] %s",argv[0]);
        for(char *const*p=argv+1;*p;p++) fprintf(stdout," %s",*p);
        fprintf(stdout,"\n");
        return 0;
    }
    pid_t pid=fork();
    if(pid<0) return -1;
    if(pid==0){
        execvp(argv[0],argv);
        _exit(127);
    }
    int status; waitpid(pid,&status,0);
    return WIFEXITED(status)?WEXITSTATUS(status):-1;
}

// Trim whitespace
static char *trim(char *s){
    char *e=s+strlen(s)-1;
    while(e>=s&&isspace(*e))*e--=0;
    while(*s&&isspace(*s))s++;
    return s;
}

// Backup current ruleset
static void backup_ruleset(void){
    syslog(LOG_INFO,"Backing up rules to %s",BACKUP_FILE);
    if(!dry_run){
        int fd=open(BACKUP_FILE,O_WRONLY|O_CREAT|O_TRUNC,0640);
        if(fd<0) syslog(LOG_ERR,"open backup: %s",strerror(errno));
        else{
            // nft list ruleset > backup
            int pipefd[2]; pipe(pipefd);
            if(fork()==0){
                dup2(fd,1); close(pipefd[0]); close(fd);
                execlp("nft","nft","list","ruleset",NULL);
                _exit(1);
            }
            close(pipefd[1]); close(fd);
            wait(NULL);
        }
    }
}

// Restore backup
static void restore_ruleset(void){
    syslog(LOG_INFO,"Restoring ruleset from %s",BACKUP_FILE);
    if(!dry_run){
        char *cmd[]={"nft","-f",(char*)BACKUP_FILE,NULL};
        run_cmd(cmd);
    }
}

// Apply config.conf (flush + load)
static void apply_config(void){
    syslog(LOG_INFO,"Applying config %s",cfg_path);
    FILE *cf=fopen(cfg_path,"r");
    if(!cf){ syslog(LOG_ERR,"open cfg: %s",strerror(errno)); return; }
    char line[MAX_LINE], *cmd;
    // first flush
    char *flush[]={"nft","flush","ruleset",NULL}; run_cmd(flush);

    while(fgets(line,sizeof(line),cf)&&!terminate){
        cmd=trim(line);
        if(!*cmd||cmd[0]=='#') continue;
        // build argv[]
        char *args[MAX_LINE/16];
        int  i=0;
        args[i++]=strdup("nft");
        char *tok=strtok(cmd," ");
        while(tok) args[i++]=tok, tok=strtok(NULL," ");
        args[i]=NULL;
        run_cmd(args);
    }
    fclose(cf);
}

// Watch config for changes and reload on SIGHUP or modify
static void watch_config(void){
    int fd=inotify_init1(IN_NONBLOCK);
    int wd=inotify_add_watch(fd,cfg_path,IN_CLOSE_WRITE);
    char buf[BUF_LEN];
    struct timespec ts={0,500000000}; // 0.5s
    while(!terminate){
        if(reload_cfg){
            apply_config();
            reload_cfg=0;
        }
        int len=read(fd,buf,BUF_LEN);
        if(len>0){
            apply_config();
        }
        nanosleep(&ts,NULL);
    }
    inotify_rm_watch(fd,wd);
    close(fd);
}
