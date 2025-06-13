// firewall.c v1.0.0
// ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
// Firewall user-space “all-in-one” in C
// • -u : apt update & upgrade
// • -d : dry-run
// • -s : status (nft list ruleset)
// • -c : config path (default config.conf)
// • -l : logfile aggiuntivo
// • syslog + append-file, daemon, pidfile, hot-reload, backup/restore, metrics

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

#define MAX_LINE       512
#define EVENT_SIZE     (sizeof(struct inotify_event))
#define BUF_LEN        (1024*(EVENT_SIZE+16))
#define MIN_NFT_VER    "0.9.0"
#define DEFAULT_CFG    "config.conf"
#define PID_FILE       "/var/run/fwctl.pid"
#define BACKUP_FILE    "/var/lib/fwctl/ruleset.bak"
#define METRICS_FILE   "/var/lib/fwctl/metrics.prom"

// stati globali
static int dry_run=0, do_update=0, do_status=0;
static char *cfg_path=DEFAULT_CFG;
static FILE *lf=NULL;
static volatile sig_atomic_t reload_cfg=0, terminate=0;
static unsigned long cnt_ok=0, cnt_fail=0;

// prototipi
static void usage(const char *p);
static void daemonize(const char *pidfile);
static void handle_signal(int);
static int  check_nft(void);
static int  run_cmd(char *const argv[]);
static char *trim(char *s);
static void backup_ruleset(void);
static void restore_ruleset(void);
static void apply_config(void);
static void watch_config(void);
static void write_metrics(void);

int main(int argc, char *argv[]){
    int opt;
    openlog("fwctl",LOG_PID|LOG_CONS,LOG_DAEMON);
    setlogmask(LOG_UPTO(LOG_INFO));

    while((opt=getopt(argc,argv,"c:duls:l:h"))!=-1){
      switch(opt){
        case 'c': cfg_path=optarg;           break;
        case 'd': dry_run=1;                 break;
        case 'u': do_update=1;               break;
        case 's': do_status=1;               break;
        case 'l': lf=fopen(optarg, dry_run?"w":"a");
                  if(!lf) syslog(LOG_ERR,"open log %s: %s",optarg,strerror(errno));
                  break;
        case 'h':
        default:  usage(argv[0]);
      }
    }

    if(geteuid()!=0){
      fprintf(stderr,"Errore: serve root\n"); exit(2);
    }
    if(check_nft()) exit(2);

    daemonize(PID_FILE);
    signal(SIGHUP, handle_signal);
    signal(SIGTERM,handle_signal);
    signal(SIGINT, handle_signal);

    if(do_status){
      char *s[]={ "nft","list","ruleset",NULL};
      run_cmd(s); write_metrics(); exit(0);
    }

    if(do_update){
      syslog(LOG_INFO,"apt-get update/upgrade");
      char *u1[]={"apt-get","update","-y",NULL};
      char *u2[]={"apt-get","upgrade","-y",NULL};
      run_cmd(u1); run_cmd(u2);
    }

    backup_ruleset();
    apply_config();
    watch_config();
    restore_ruleset();
    write_metrics();

    syslog(LOG_INFO,"Terminated: OK=%lu FAIL=%lu",cnt_ok,cnt_fail);
    closelog(); if(lf) fclose(lf);
    return cnt_fail?1:0;
}

static void usage(const char *p){
  fprintf(stderr,
    "Usage: %s [opts]\n"
    " -c FILE   config file (default %s)\n"
    " -d        dry-run\n"
    " -u        apt-get update & upgrade\n"
    " -s        status (show ruleset) and exit\n"
    " -l FILE   append logfile\n"
    " -h        help\n",p,DEFAULT_CFG);
  exit(2);
}

static void daemonize(const char *pidfile){
  pid_t pid=fork(); if(pid<0) exit(2);
  if(pid>0) exit(0);
  setsid(); if(fork()>0) exit(0);
  umask(0); chdir("/"); close(STDIN_FILENO);
  close(STDOUT_FILENO); close(STDERR_FILENO);
  int fd=open(pidfile,O_RDWR|O_CREAT,0640);
  if(fd>=0){ char buf[32]; snprintf(buf,32,"%d\n",getpid());
             write(fd,buf,strlen(buf)); close(fd);}
}

static void handle_signal(int sig){
  if(sig==SIGHUP)   reload_cfg=1;
  if(sig==SIGTERM||sig==SIGINT) terminate=1;
}

static int check_nft(void){
  int pipefd[2]; pipe(pipefd);
  if(fork()==0){
    dup2(pipefd[1],1); close(pipefd[0]); execlp("nft","nft","--version",NULL); _exit(1);
  }
  close(pipefd[1]);
  char buf[64]; read(pipefd[0],buf,64); close(pipefd[0]);
  if(!strstr(buf,MIN_NFT_VER)){
    syslog(LOG_ERR,"nft ver < %s: %s",MIN_NFT_VER,buf);
    return 1;
  }
  syslog(LOG_INFO,"nft OK: %s",buf);
  return 0;
}

static int run_cmd(char *const argv[]){
  if(dry_run){
    fprintf(stdout,"[DRY] %s",argv[0]);
    for(char *const*p=argv+1;*p;p++) fprintf(stdout," %s",*p);
    fprintf(stdout,"\n");
    return 0;
  }
  pid_t pid=fork(); if(pid<0) return -1;
  if(pid==0){ execvp(argv[0],argv); _exit(127); }
  int st; waitpid(pid,&st,0);
  int ok = WIFEXITED(st)&&WEXITSTATUS(st)==0;
  if(ok) cnt_ok++; else cnt_fail++;
  return ok?0:1;
}

static char *trim(char *s){
  char *e=s+strlen(s)-1;
  while(e>=s&&isspace(*e))*e--=0;
  while(*s&&isspace(*s))s++;
  return s;
}

static void backup_ruleset(void){
  syslog(LOG_INFO,"Backup to %s",BACKUP_FILE);
  if(dry_run) return;
  mkdir("/var/lib/fwctl",0755);
  int fd=open(BACKUP_FILE,O_WRONLY|O_CREAT|O_TRUNC,0640);
  if(fd<0){ syslog(LOG_ERR,"open bak: %s",strerror(errno)); return; }
  int pipefd[2]; pipe(pipefd);
  if(fork()==0){
    dup2(fd,1); close(pipefd[0]);
    execlp("nft","nft","list","ruleset",NULL); _exit(1);
  }
  close(pipefd[1]); close(fd); wait(NULL);
}

static void restore_ruleset(void){
  syslog(LOG_INFO,"Restore from %s",BACKUP_FILE);
  if(dry_run) return;
  char *r[]={"nft","-f",(char*)BACKUP_FILE,NULL};
  run_cmd(r);
}

static void apply_config(void){
  syslog(LOG_INFO,"Apply config %s",cfg_path);
  FILE *cf=fopen(cfg_path,"r");
  if(!cf){ syslog(LOG_ERR,"open cfg: %s",strerror(errno)); return; }
  // flush
  char *f[]={"nft","flush","ruleset",NULL}; run_cmd(f);

  char line[MAX_LINE];
  while(!terminate && fgets(line,sizeof(line),cf)){
    char *c=trim(line);
    if(!*c||*c=='#') continue;
    // split into argv[]
    char *args[MAX_LINE/16],*tok=strtok(c," ");
    int i=0; args[i++]=strdup("nft");
    while(tok) args[i++]=tok,tok=strtok(NULL," ");
    args[i]=NULL;
    run_cmd(args);
  }
  fclose(cf);
}

static void watch_config(void){
  int fd=inotify_init1(IN_NONBLOCK);
  int wd=inotify_add_watch(fd,cfg_path,IN_CLOSE_WRITE);
  char buf[BUF_LEN];
  struct timespec ts={0,500000000};
  while(!terminate){
    if(reload_cfg){ apply_config(); reload_cfg=0; }
    int len=read(fd,buf,BUF_LEN);
    if(len>0) apply_config();
    nanosleep(&ts,NULL);
  }
  inotify_rm_watch(fd,wd); close(fd);
}

static void write_metrics(void){
  if(dry_run) return;
  FILE *m=fopen(METRICS_FILE,"w");
  if(!m){ syslog(LOG_ERR,"open met: %s",strerror(errno)); return; }
  fprintf(m,
    "# HELP fwctl_rules_applied_total Rules successfully applied\n"
    "# TYPE fwctl_rules_applied_total counter\n"
    "fwctl_rules_applied_total %lu\n"
    "# HELP fwctl_rules_failed_total Rules failed\n"
    "# TYPE fwctl_rules_failed_total counter\n"
    "fwctl_rules_failed_total %lu\n",
    cnt_ok, cnt_fail);
  fclose(m);
}
