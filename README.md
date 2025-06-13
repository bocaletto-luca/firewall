# 🔥 Firewall v1.0.0
#### Author: Bocaletto Luca

Un **firewall user-space all-in-one** in C, senza dipendenze esterne, token o registrazioni, pronto per la produzione.

---

## 📋 Caratteristiche

- `-u` : `apt-get update && apt-get upgrade -y`  
- `-d` : **dry-run**, stampa i comandi senza executarli  
- `-s` : **status**, lista lo stato corrente (`nft list ruleset`)  
- `-c FILE` : path al file di configurazione (default `config.conf`)  
- `-l FILE` : logfile aggiuntivo (append) oltre a `syslog`  
- **Daemon** con PID-file (`/var/run/fwctl.pid`)  
- **Hot-reload** su `SIGHUP` e inotify (`config.conf`)  
- **Backup/Restore** automatico del ruleset (`/var/lib/fwctl/ruleset.bak`)  
- **IPv4/IPv6/NAT** via config generico  
- **Metriche Prometheus** in `/var/lib/fwctl/metrics.prom`  
- **Logging strutturato** su `syslog` (LOG_DAEMON) e file opzionale  

---

## 📂 Layout del repository


---

## ⚙️  Configurazione

Crea un file `config.conf` nella root del repo, con comandi `nft` (senza il prefisso `nft`), ad esempio:

# -----------------------------
# NAT Example
# -----------------------------
    add table ip nat
    add chain ip nat prerouting  { type nat hook prerouting priority 0; }
    add chain ip nat postrouting { type nat hook postrouting priority 100; }
    add rule  ip nat postrouting oif "eth0" masquerade

# -----------------------------
# IPv4 Filter
# -----------------------------
    add table inet filter
    add chain inet filter input   { type filter hook input priority 0; policy drop; }
    add rule  inet filter input   ct state { ESTABLISHED,RELATED } accept
    add rule  inet filter input   ip saddr 0.0.0.0/0 tcp dport 22 accept
    add rule  inet filter input   counter drop

# -----------------------------
# IPv6 Filter
# -----------------------------
    add table ip6 filter
    add chain ip6 filter input   { type filter hook input priority 0; policy drop; }
    add rule  ip6 filter input   ip6 saddr ::/0 tcp dport 22 accept
    add rule  ip6 filter input   ct state { ESTABLISHED,RELATED } accept
    add rule  ip6 filter input   counter drop

## USE

# 1) Solo dry-run
    ./firewall -d

# 2) Status e exit
    sudo ./firewall -s

# 3) Update & Upgrade + apply
    sudo ./firewall -u

# 4) Apply e daemon
    sudo ./firewall -l /var/log/fwctl.log

## Systemd
#### Create 

    /etc/systemd/system/fwctl.service

    [Unit]
    Description=FWCTL Firewall Service
    After=network.target

    [Service]
    Type=simple
    ExecStart=/usr/local/bin/firewall -l /var/log/fwctl.log
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target

    sudo systemctl daemon-reload
    sudo systemctl enable --now fwctl.service

## 👤 Author
####Luca Bocaletto 
