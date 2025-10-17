"""
SSH Honeypot Implementation

Creates a realistic SSH server with synthetic Linux environment,
file system simulation, and command execution responses.
"""

import asyncio
import logging
import secrets
import time
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import asyncssh
from asyncssh import SSHServerSession, SSHServerProcess
import os
import json

logger = logging.getLogger(__name__)

@dataclass
class SyntheticFile:
    """Synthetic file system entry"""
    name: str
    path: str
    file_type: str  # 'file', 'directory', 'link'
    size: int
    permissions: str
    owner: str
    group: str
    modified_time: str
    content: Optional[str] = None
    synthetic: bool = True
    fingerprint: str = ""
    
    def __post_init__(self):
        if not self.fingerprint:
            data = f"{self.path}{self.name}{self.modified_time}"
            self.fingerprint = hashlib.sha256(data.encode()).hexdigest()[:16]

@dataclass
class CommandExecution:
    """Command execution record"""
    command: str
    args: List[str]
    timestamp: datetime
    session_id: str
    user: str
    working_directory: str
    exit_code: int
    output: str
    synthetic: bool = True

@dataclass
class SSHSession:
    """SSH session tracking"""
    session_id: str
    username: str
    ip_address: str
    start_time: datetime
    last_activity: datetime
    commands: List[CommandExecution]
    working_directory: str
    environment: Dict[str, str]
    synthetic: bool = True

class SyntheticFileSystem:
    """Simulates a realistic Linux file system"""
    
    def __init__(self):
        self.files: Dict[str, SyntheticFile] = {}
        self._create_default_filesystem()
    
    def _create_default_filesystem(self):
        """Create a realistic Linux file system structure"""
        
        # Root directories
        directories = [
            "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64",
            "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin",
            "/srv", "/sys", "/tmp", "/usr", "/var"
        ]
        
        # User directories
        user_dirs = [
            "/home/admin", "/home/admin/.ssh", "/home/admin/Documents",
            "/home/admin/Downloads", "/home/admin/scripts",
            "/home/john", "/home/sarah", "/home/backup"
        ]
        
        # System directories
        system_dirs = [
            "/etc/ssh", "/etc/apache2", "/etc/mysql", "/var/log",
            "/var/www", "/var/www/html", "/usr/bin", "/usr/sbin",
            "/usr/local", "/usr/local/bin"
        ]
        
        all_dirs = directories + user_dirs + system_dirs
        
        for dir_path in all_dirs:
            self.files[dir_path] = SyntheticFile(
                name=os.path.basename(dir_path) or "/",
                path=dir_path,
                file_type="directory",
                size=4096,
                permissions="drwxr-xr-x",
                owner="root",
                group="root",
                modified_time=(datetime.now() - timedelta(days=secrets.randbelow(30))).strftime("%b %d %H:%M")
            )
        
        # Create synthetic files
        self._create_system_files()
        self._create_user_files()
        self._create_log_files()
        self._create_config_files()
    
    def _create_system_files(self):
        """Create realistic system files"""
        system_files = [
            ("/etc/passwd", self._generate_passwd_content()),
            ("/etc/shadow", "root:$6$salt$hash...:18000:0:99999:7:::\nadmin:$6$salt$hash...:18000:0:99999:7:::"),
            ("/etc/hosts", "127.0.0.1\tlocalhost\n192.168.1.100\tcorptech-server"),
            ("/etc/hostname", "corptech-server"),
            ("/etc/os-release", 'NAME="Ubuntu"\nVERSION="20.04.3 LTS (Focal Fossa)"\nID=ubuntu'),
            ("/proc/version", "Linux version 5.4.0-91-generic (buildd@lgw01-amd64-038)"),
            ("/proc/cpuinfo", self._generate_cpuinfo()),
            ("/proc/meminfo", self._generate_meminfo()),
        ]
        
        for file_path, content in system_files:
            self.files[file_path] = SyntheticFile(
                name=os.path.basename(file_path),
                path=file_path,
                file_type="file",
                size=len(content),
                permissions="-rw-r--r--",
                owner="root",
                group="root",
                modified_time=(datetime.now() - timedelta(days=secrets.randbelow(30))).strftime("%b %d %H:%M"),
                content=content
            )
    
    def _create_user_files(self):
        """Create realistic user files"""
        user_files = [
            ("/home/admin/.bashrc", self._generate_bashrc()),
            ("/home/admin/.bash_history", self._generate_bash_history()),
            ("/home/admin/.ssh/authorized_keys", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... admin@corptech"),
            ("/home/admin/Documents/notes.txt", "Meeting notes from Q4 planning session\n- Budget review\n- New hire approvals"),
            ("/home/admin/scripts/backup.sh", "#!/bin/bash\n# Daily backup script\nrsync -av /home/ /backup/"),
            ("/root/.bash_history", "ls -la\nps aux\ntop\nsystemctl status apache2\n"),
        ]
        
        for file_path, content in user_files:
            self.files[file_path] = SyntheticFile(
                name=os.path.basename(file_path),
                path=file_path,
                file_type="file",
                size=len(content),
                permissions="-rw-------" if ".ssh" in file_path or "history" in file_path else "-rw-r--r--",
                owner="admin" if "/home/admin" in file_path else "root",
                group="admin" if "/home/admin" in file_path else "root",
                modified_time=(datetime.now() - timedelta(days=secrets.randbelow(7))).strftime("%b %d %H:%M"),
                content=content
            )
    
    def _create_log_files(self):
        """Create realistic log files"""
        log_files = [
            ("/var/log/auth.log", self._generate_auth_log()),
            ("/var/log/syslog", self._generate_syslog()),
            ("/var/log/apache2/access.log", self._generate_apache_log()),
            ("/var/log/mysql/error.log", self._generate_mysql_log()),
        ]
        
        for file_path, content in log_files:
            self.files[file_path] = SyntheticFile(
                name=os.path.basename(file_path),
                path=file_path,
                file_type="file",
                size=len(content),
                permissions="-rw-r-----",
                owner="root",
                group="adm",
                modified_time=datetime.now().strftime("%b %d %H:%M"),
                content=content
            )
    
    def _create_config_files(self):
        """Create realistic configuration files"""
        config_files = [
            ("/etc/ssh/sshd_config", self._generate_sshd_config()),
            ("/etc/apache2/apache2.conf", "# Apache configuration\nServerRoot /etc/apache2\nPidFile ${APACHE_PID_FILE}"),
            ("/etc/mysql/my.cnf", "[mysql]\ndefault-character-set=utf8\n[mysqld]\nbind-address=127.0.0.1"),
        ]
        
        for file_path, content in config_files:
            self.files[file_path] = SyntheticFile(
                name=os.path.basename(file_path),
                path=file_path,
                file_type="file",
                size=len(content),
                permissions="-rw-r--r--",
                owner="root",
                group="root",
                modified_time=(datetime.now() - timedelta(days=secrets.randbelow(60))).strftime("%b %d %H:%M"),
                content=content
            )
    
    def _generate_passwd_content(self) -> str:
        """Generate realistic /etc/passwd content"""
        return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
admin:x:1000:1000:System Administrator:/home/admin:/bin/bash
john:x:1001:1001:John Smith:/home/john:/bin/bash
sarah:x:1002:1002:Sarah Johnson:/home/sarah:/bin/bash
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin"""
    
    def _generate_bashrc(self) -> str:
        """Generate realistic .bashrc content"""
        return """# ~/.bashrc: executed by bash(1) for non-login shells.

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

if [ "$color_prompt" = yes ]; then
    PS1='\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '
else
    PS1='\\u@\\h:\\w\\$ '
fi

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias grep='grep --color=auto'
fi

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Custom aliases for admin tasks
alias logs='tail -f /var/log/syslog'
alias backup='sudo /home/admin/scripts/backup.sh'
alias status='systemctl status'"""
    
    def _generate_bash_history(self) -> str:
        """Generate realistic bash history"""
        commands = [
            "ls -la", "cd /var/log", "tail -f syslog", "ps aux", "top",
            "systemctl status apache2", "systemctl restart mysql", "df -h",
            "free -m", "netstat -tulpn", "iptables -L", "crontab -l",
            "sudo apt update", "sudo apt upgrade", "vim /etc/hosts",
            "cat /etc/passwd", "who", "w", "last", "history",
            "ssh-keygen -t rsa", "chmod 600 ~/.ssh/id_rsa", "scp file.txt user@server:",
            "mysql -u root -p", "mysqldump -u root -p database > backup.sql",
            "tar -czf backup.tar.gz /home/", "rsync -av /home/ /backup/",
            "find /var/log -name '*.log' -mtime +30", "grep 'error' /var/log/apache2/error.log"
        ]
        return "\n".join(commands)
    
    def _generate_cpuinfo(self) -> str:
        """Generate realistic /proc/cpuinfo"""
        return """processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 142
model name	: Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz
stepping	: 12
microcode	: 0xf0
cpu MHz		: 1800.000
cache size	: 8192 KB
physical id	: 0
siblings	: 8
core id		: 0
cpu cores	: 4
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 22
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa itlb_multihit srbds
bogomips	: 3999.93
clflush size	: 64
cache_alignment	: 64
address sizes	: 39 bits physical, 48 bits virtual
power management:"""
    
    def _generate_meminfo(self) -> str:
        """Generate realistic /proc/meminfo"""
        return """MemTotal:        8052736 kB
MemFree:         2847392 kB
MemAvailable:    6234568 kB
Buffers:          156432 kB
Cached:          3045672 kB
SwapCached:            0 kB
Active:          2456789 kB
Inactive:        2234567 kB
Active(anon):    1489234 kB
Inactive(anon):   123456 kB
Active(file):     967555 kB
Inactive(file):  2111111 kB
Unevictable:          32 kB
Mlocked:              32 kB
SwapTotal:       2097148 kB
SwapFree:        2097148 kB
Dirty:               128 kB
Writeback:             0 kB
AnonPages:       1489234 kB
Mapped:           456789 kB
Shmem:            123456 kB
KReclaimable:     234567 kB
Slab:             345678 kB
SReclaimable:     234567 kB
SUnreclaim:       111111 kB
KernelStack:       12345 kB
PageTables:        23456 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:     6123516 kB
Committed_AS:    3456789 kB
VmallocTotal:   34359738367 kB
VmallocUsed:       45678 kB
VmallocChunk:          0 kB
Percpu:             2345 kB
HardwareCorrupted:     0 kB
AnonHugePages:    567890 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
CmaTotal:              0 kB
CmaFree:               0 kB
HugePages_Total:       0
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
Hugetlb:               0 kB
DirectMap4k:      234567 kB
DirectMap2M:     7890123 kB
DirectMap1G:           0 kB"""
    
    def _generate_auth_log(self) -> str:
        """Generate realistic auth.log entries"""
        now = datetime.now()
        entries = []
        
        for i in range(10):
            timestamp = (now - timedelta(hours=i)).strftime("%b %d %H:%M:%S")
            entries.extend([
                f"{timestamp} corptech-server sshd[{1000+i}]: Accepted publickey for admin from 192.168.1.50 port 22 ssh2: RSA SHA256:abc123",
                f"{timestamp} corptech-server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/systemctl status apache2",
                f"{timestamp} corptech-server sshd[{1010+i}]: Connection closed by 192.168.1.50 port 22 [preauth]"
            ])
        
        return "\n".join(entries)
    
    def _generate_syslog(self) -> str:
        """Generate realistic syslog entries"""
        now = datetime.now()
        entries = []
        
        for i in range(15):
            timestamp = (now - timedelta(minutes=i*10)).strftime("%b %d %H:%M:%S")
            entries.extend([
                f"{timestamp} corptech-server systemd[1]: Started Session 123 of user admin.",
                f"{timestamp} corptech-server kernel: [12345.678901] TCP: request_sock_TCP: Possible SYN flooding on port 22.",
                f"{timestamp} corptech-server apache2[2345]: [notice] Apache/2.4.41 (Ubuntu) configured",
                f"{timestamp} corptech-server mysql[3456]: [Note] mysqld: ready for connections."
            ])
        
        return "\n".join(entries)
    
    def _generate_apache_log(self) -> str:
        """Generate realistic Apache access log"""
        now = datetime.now()
        entries = []
        
        for i in range(20):
            timestamp = (now - timedelta(minutes=i*5)).strftime("%d/%b/%Y:%H:%M:%S +0000")
            ip = f"192.168.1.{50 + (i % 50)}"
            entries.append(f'{ip} - - [{timestamp}] "GET /admin/dashboard HTTP/1.1" 200 2345 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"')
        
        return "\n".join(entries)
    
    def _generate_mysql_log(self) -> str:
        """Generate realistic MySQL error log"""
        now = datetime.now()
        entries = []
        
        for i in range(5):
            timestamp = (now - timedelta(hours=i*2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            entries.extend([
                f"{timestamp} 0 [Note] mysqld: ready for connections.",
                f"{timestamp} 0 [Note] Event Scheduler: Loaded 0 events",
                f"{timestamp} 0 [Note] /usr/sbin/mysqld: Normal shutdown"
            ])
        
        return "\n".join(entries)
    
    def _generate_sshd_config(self) -> str:
        """Generate realistic sshd_config"""
        return """# Package generated configuration file
# See the sshd_config(5) manpage for details

# What ports, IPs and protocols we listen for
Port 22
# Use these options to restrict which interfaces/protocols sshd will bind to
#ListenAddress ::
#ListenAddress 0.0.0.0
Protocol 2
# HostKeys for protocol version 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
#Privilege Separation is turned on for security
UsePrivilegeSeparation yes

# Lifetime and size of ephemeral version 1 server key
KeyRegenerationInterval 3600
ServerKeyBits 1024

# Logging
SyslogFacility AUTH
LogLevel INFO

# Authentication:
LoginGraceTime 120
PermitRootLogin prohibit-password
StrictModes yes

RSAAuthentication yes
PubkeyAuthentication yes
#AuthorizedKeysFile	%h/.ssh/authorized_keys

# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes
# For this to work you will also need host keys in /etc/ssh_known_hosts
RhostsRSAAuthentication no
# similar for protocol version 2
HostbasedAuthentication no
# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
#IgnoreUserKnownHosts yes

# To enable empty passwords, change to yes (NOT RECOMMENDED)
PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Change to no to disable tunnelled clear text passwords
PasswordAuthentication yes

# Kerberos options
#KerberosAuthentication no
#KerberosGetAFSToken no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes

X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
#UseLogin no

#MaxStartups 10:30:60
#Banner /etc/issue.net

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

Subsystem sftp /usr/lib/openssh/sftp-server

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes"""
    
    def get_file(self, path: str) -> Optional[SyntheticFile]:
        """Get file by path"""
        return self.files.get(path)
    
    def list_directory(self, path: str) -> List[SyntheticFile]:
        """List files in directory"""
        if not path.endswith('/'):
            path += '/'
        
        files = []
        for file_path, file_obj in self.files.items():
            if file_path.startswith(path) and file_path != path:
                # Get relative path
                relative = file_path[len(path):]
                # Only include direct children (no subdirectories)
                if '/' not in relative.strip('/'):
                    files.append(file_obj)
        
        return sorted(files, key=lambda f: f.name)
    
    def file_exists(self, path: str) -> bool:
        """Check if file exists"""
        return path in self.files

class CommandSimulator:
    """Simulates Linux command execution with realistic responses"""
    
    def __init__(self, filesystem: SyntheticFileSystem):
        self.filesystem = filesystem
        self.current_directory = "/home/admin"
        self.environment = {
            "HOME": "/home/admin",
            "USER": "admin",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PWD": "/home/admin",
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8"
        }
    
    def execute_command(self, command: str, args: List[str]) -> Tuple[str, int]:
        """Execute a command and return output and exit code"""
        
        # Handle different commands
        if command == "ls":
            return self._cmd_ls(args)
        elif command == "pwd":
            return self.current_directory + "\n", 0
        elif command == "cd":
            return self._cmd_cd(args)
        elif command == "cat":
            return self._cmd_cat(args)
        elif command == "whoami":
            return "admin\n", 0
        elif command == "id":
            return "uid=1000(admin) gid=1000(admin) groups=1000(admin),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare)\n", 0
        elif command == "uname":
            return self._cmd_uname(args)
        elif command == "ps":
            return self._cmd_ps(args)
        elif command == "top":
            return "top - 14:30:22 up 45 days, 12:34,  2 users,  load average: 0.15, 0.25, 0.30\nTasks: 123 total,   1 running, 122 sleeping,   0 stopped,   0 zombie\n%Cpu(s):  2.3 us,  1.2 sy,  0.0 ni, 96.2 id,  0.3 wa,  0.0 hi,  0.0 si,  0.0 st\nMiB Mem :   7864.0 total,   2780.5 free,   2401.2 used,   2682.3 buff/cache\nMiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   6087.4 avail Mem\n\n  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n 1234 admin     20   0  123456   7890   5432 S   1.3   0.1   0:12.34 bash\n 5678 root      20   0  987654  12345   8765 S   0.7   0.2   1:23.45 systemd\n", 0
        elif command == "df":
            return self._cmd_df(args)
        elif command == "free":
            return self._cmd_free(args)
        elif command == "netstat":
            return self._cmd_netstat(args)
        elif command == "ss":
            return self._cmd_ss(args)
        elif command == "systemctl":
            return self._cmd_systemctl(args)
        elif command == "service":
            return self._cmd_service(args)
        elif command == "history":
            return self._cmd_history(args)
        elif command == "env":
            return "\n".join([f"{k}={v}" for k, v in self.environment.items()]) + "\n", 0
        elif command == "which":
            return self._cmd_which(args)
        elif command == "find":
            return self._cmd_find(args)
        elif command == "grep":
            return self._cmd_grep(args)
        elif command == "tail":
            return self._cmd_tail(args)
        elif command == "head":
            return self._cmd_head(args)
        elif command == "w":
            return " 14:30:22 up 45 days, 12:34,  2 users,  load average: 0.15, 0.25, 0.30\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nadmin    pts/0    192.168.1.50     14:25    0.00s  0.12s  0.01s w\nroot     tty1     -                Jan15   45days  0.03s  0.03s -bash\n", 0
        elif command == "who":
            return "admin    pts/0        2024-01-15 14:25 (192.168.1.50)\nroot     tty1         2024-01-01 09:00\n", 0
        elif command == "last":
            return "admin    pts/0        192.168.1.50     Mon Jan 15 14:25   still logged in\nadmin    pts/0        192.168.1.50     Mon Jan 15 09:30 - 12:45  (03:15)\nroot     tty1                          Mon Jan  1 09:00   still logged in\n", 0
        elif command == "uptime":
            return " 14:30:22 up 45 days, 12:34,  2 users,  load average: 0.15, 0.25, 0.30\n", 0
        elif command == "date":
            return datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y") + "\n", 0
        elif command == "hostname":
            return "corptech-server\n", 0
        elif command == "mount":
            return "/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\n/dev/sda2 on /home type ext4 (rw,relatime)\ntmpfs on /tmp type tmpfs (rw,nosuid,nodev)\n", 0
        elif command == "lsblk":
            return "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT\nsda      8:0    0   50G  0 disk\n├─sda1   8:1    0   45G  0 part /\n└─sda2   8:2    0    5G  0 part /home\n", 0
        elif command in ["sudo", "su"]:
            return "Sorry, user admin is not allowed to run sudo on this host.\n", 1
        else:
            return f"bash: {command}: command not found\n", 127
    
    def _cmd_ls(self, args: List[str]) -> Tuple[str, int]:
        """Simulate ls command"""
        show_all = "-a" in args or "-la" in args or "-al" in args
        long_format = "-l" in args or "-la" in args or "-al" in args
        
        # Get target directory
        target_dir = self.current_directory
        for arg in args:
            if not arg.startswith("-"):
                target_dir = arg if arg.startswith("/") else os.path.join(self.current_directory, arg)
                break
        
        if not self.filesystem.file_exists(target_dir):
            return f"ls: cannot access '{target_dir}': No such file or directory\n", 2
        
        files = self.filesystem.list_directory(target_dir)
        
        if not show_all:
            files = [f for f in files if not f.name.startswith(".")]
        
        if long_format:
            output = []
            total_size = sum(f.size for f in files) // 1024
            output.append(f"total {total_size}")
            
            for file in files:
                output.append(f"{file.permissions} 1 {file.owner} {file.group} {file.size:>8} {file.modified_time} {file.name}")
            
            return "\n".join(output) + "\n", 0
        else:
            return "  ".join([f.name for f in files]) + "\n", 0
    
    def _cmd_cd(self, args: List[str]) -> Tuple[str, int]:
        """Simulate cd command"""
        if not args:
            self.current_directory = self.environment["HOME"]
            return "", 0
        
        target = args[0]
        if target.startswith("/"):
            new_dir = target
        else:
            new_dir = os.path.join(self.current_directory, target)
        
        # Normalize path
        new_dir = os.path.normpath(new_dir)
        
        if self.filesystem.file_exists(new_dir):
            file_obj = self.filesystem.get_file(new_dir)
            if file_obj and file_obj.file_type == "directory":
                self.current_directory = new_dir
                self.environment["PWD"] = new_dir
                return "", 0
            else:
                return f"bash: cd: {target}: Not a directory\n", 1
        else:
            return f"bash: cd: {target}: No such file or directory\n", 1
    
    def _cmd_cat(self, args: List[str]) -> Tuple[str, int]:
        """Simulate cat command"""
        if not args:
            return "cat: missing file operand\n", 1
        
        output = []
        for filename in args:
            if filename.startswith("/"):
                filepath = filename
            else:
                filepath = os.path.join(self.current_directory, filename)
            
            file_obj = self.filesystem.get_file(filepath)
            if file_obj:
                if file_obj.file_type == "file" and file_obj.content:
                    output.append(file_obj.content)
                elif file_obj.file_type == "directory":
                    return f"cat: {filename}: Is a directory\n", 1
                else:
                    output.append("")
            else:
                return f"cat: {filename}: No such file or directory\n", 1
        
        return "\n".join(output) + "\n", 0
    
    def _cmd_uname(self, args: List[str]) -> Tuple[str, int]:
        """Simulate uname command"""
        if "-a" in args:
            return "Linux corptech-server 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux\n", 0
        elif "-r" in args:
            return "5.4.0-91-generic\n", 0
        elif "-n" in args:
            return "corptech-server\n", 0
        else:
            return "Linux\n", 0
    
    def _cmd_ps(self, args: List[str]) -> Tuple[str, int]:
        """Simulate ps command"""
        if "aux" in " ".join(args):
            return """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 225468  9876 ?        Ss   Jan01   0:12 /sbin/init splash
root         2  0.0  0.0      0     0 ?        S    Jan01   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   Jan01   0:00 [rcu_gp]
root         4  0.0  0.0      0     0 ?        I<   Jan01   0:00 [rcu_par_gp]
root       123  0.0  0.1  12345  6789 ?        Ss   Jan01   0:05 /usr/sbin/sshd -D
root       456  0.0  0.2  23456  7890 ?        Ss   Jan01   1:23 /usr/sbin/apache2 -k start
mysql      789  0.1  2.3 987654 123456 ?       Sl   Jan01  12:34 /usr/sbin/mysqld
admin     1234  0.0  0.1  12345  5678 pts/0    Ss   14:25   0:00 -bash
admin     5678  0.0  0.0   8765  2345 pts/0    R+   14:30   0:00 ps aux
""", 0
        else:
            return """  PID TTY          TIME CMD
 1234 pts/0    00:00:00 bash
 5678 pts/0    00:00:00 ps
""", 0
    
    def _cmd_df(self, args: List[str]) -> Tuple[str, int]:
        """Simulate df command"""
        if "-h" in args:
            return """Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        45G   12G   31G  28% /
/dev/sda2       4.9G  1.2G  3.5G  26% /home
tmpfs           3.9G     0  3.9G   0% /dev/shm
tmpfs           788M  1.2M  787M   1% /run
tmpfs           5.0M  4.0K  5.0M   1% /run/lock
tmpfs           3.9G     0  3.9G   0% /sys/fs/cgroup
""", 0
        else:
            return """Filesystem     1K-blocks     Used Available Use% Mounted on
/dev/sda1       47185920 12582912  32424960  28% /
/dev/sda2        5123456  1234567   3678901  26% /home
tmpfs            4048576        0   4048576   0% /dev/shm
tmpfs             806912     1234    805678   1% /run
tmpfs               5120        4      5116   1% /run/lock
tmpfs            4048576        0   4048576   0% /sys/fs/cgroup
""", 0
    
    def _cmd_free(self, args: List[str]) -> Tuple[str, int]:
        """Simulate free command"""
        if "-m" in args:
            return """              total        used        free      shared  buff/cache   available
Mem:           7864        2401        2780         123        2682        6087
Swap:          2048           0        2048
""", 0
        elif "-h" in args:
            return """              total        used        free      shared  buff/cache   available
Mem:           7.7G        2.3G        2.7G        123M        2.6G        5.9G
Swap:          2.0G          0B        2.0G
""", 0
        else:
            return """              total        used        free      shared  buff/cache   available
Mem:        8052736     2459648     2847392      126976     2745696     6234568
Swap:       2097148           0     2097148
""", 0
    
    def _cmd_netstat(self, args: List[str]) -> Tuple[str, int]:
        """Simulate netstat command"""
        if "tulpn" in " ".join(args):
            return """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      123/sshd            
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      789/mysqld          
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      456/apache2         
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      456/apache2         
tcp6       0      0 :::22                   :::*                    LISTEN      123/sshd            
tcp6       0      0 :::80                   :::*                    LISTEN      456/apache2         
tcp6       0      0 :::443                  :::*                    LISTEN      456/apache2         
udp        0      0 0.0.0.0:68              0.0.0.0:*                           234/dhclient        
udp        0      0 127.0.0.1:53            0.0.0.0:*                           345/systemd-resolve 
""", 0
        else:
            return """Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 192.168.1.100:22        192.168.1.50:54321      ESTABLISHED
""", 0
    
    def _cmd_ss(self, args: List[str]) -> Tuple[str, int]:
        """Simulate ss command"""
        return """Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
tcp    LISTEN     0      128          0.0.0.0:22                      0.0.0.0:*                  
tcp    LISTEN     0      80         127.0.0.1:3306                    0.0.0.0:*                  
tcp    LISTEN     0      128          0.0.0.0:80                      0.0.0.0:*                  
tcp    LISTEN     0      128          0.0.0.0:443                     0.0.0.0:*                  
tcp    ESTAB      0      0      192.168.1.100:22               192.168.1.50:54321              
""", 0
    
    def _cmd_systemctl(self, args: List[str]) -> Tuple[str, int]:
        """Simulate systemctl command"""
        if len(args) >= 2 and args[0] == "status":
            service = args[1]
            if service == "apache2":
                return f"""● apache2.service - The Apache HTTP Server
   Loaded: loaded (/lib/systemd/system/apache2.service; enabled; vendor preset: enabled)
   Active: active (running) since Mon 2024-01-01 09:00:00 UTC; 2 weeks 1 day ago
     Docs: https://httpd.apache.org/docs/2.4/
 Main PID: 456 (apache2)
    Tasks: 55 (limit: 4915)
   Memory: 12.3M
   CGroup: /system.slice/apache2.service
           ├─456 /usr/sbin/apache2 -k start
           ├─789 /usr/sbin/apache2 -k start
           └─890 /usr/sbin/apache2 -k start

Jan 15 14:30:00 corptech-server systemd[1]: Started The Apache HTTP Server.
""", 0
            elif service == "mysql":
                return f"""● mysql.service - MySQL Community Server
   Loaded: loaded (/lib/systemd/system/mysql.service; enabled; vendor preset: enabled)
   Active: active (running) since Mon 2024-01-01 09:00:00 UTC; 2 weeks 1 day ago
     Docs: man:mysqld(8)
           http://dev.mysql.com/doc/refman/en/using-systemd.html
 Main PID: 789 (mysqld)
   Status: "Server is operational"
    Tasks: 39 (limit: 4915)
   Memory: 178.2M
   CGroup: /system.slice/mysql.service
           └─789 /usr/sbin/mysqld

Jan 15 14:30:00 corptech-server systemd[1]: Started MySQL Community Server.
""", 0
            else:
                return f"Unit {service}.service could not be found.\n", 4
        else:
            return "systemctl: missing command\n", 1
    
    def _cmd_service(self, args: List[str]) -> Tuple[str, int]:
        """Simulate service command"""
        if len(args) >= 2:
            service = args[0]
            action = args[1]
            if action == "status":
                return f" * {service} is running\n", 0
            else:
                return f" * {action} {service}                                                         [ OK ]\n", 0
        else:
            return "Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]\n", 1
    
    def _cmd_history(self, args: List[str]) -> Tuple[str, int]:
        """Simulate history command"""
        history_file = self.filesystem.get_file("/home/admin/.bash_history")
        if history_file and history_file.content:
            lines = history_file.content.split('\n')
            numbered_lines = [f"  {i+1}  {line}" for i, line in enumerate(lines) if line.strip()]
            return "\n".join(numbered_lines) + "\n", 0
        else:
            return "", 0
    
    def _cmd_which(self, args: List[str]) -> Tuple[str, int]:
        """Simulate which command"""
        if not args:
            return "which: missing operand\n", 1
        
        command = args[0]
        common_commands = {
            "bash": "/bin/bash",
            "ls": "/bin/ls",
            "cat": "/bin/cat",
            "grep": "/bin/grep",
            "find": "/usr/bin/find",
            "ps": "/bin/ps",
            "top": "/usr/bin/top",
            "systemctl": "/bin/systemctl",
            "service": "/usr/sbin/service",
            "mysql": "/usr/bin/mysql",
            "apache2": "/usr/sbin/apache2"
        }
        
        if command in common_commands:
            return common_commands[command] + "\n", 0
        else:
            return "", 1
    
    def _cmd_find(self, args: List[str]) -> Tuple[str, int]:
        """Simulate find command"""
        # Simple find simulation
        if not args:
            return "find: missing operand\n", 1
        
        # Basic find simulation - just return some realistic results
        return """/home/admin
/home/admin/.bashrc
/home/admin/.bash_history
/home/admin/.ssh
/home/admin/.ssh/authorized_keys
/home/admin/Documents
/home/admin/Documents/notes.txt
/home/admin/scripts
/home/admin/scripts/backup.sh
""", 0
    
    def _cmd_grep(self, args: List[str]) -> Tuple[str, int]:
        """Simulate grep command"""
        if len(args) < 2:
            return "grep: missing operand\n", 1
        
        pattern = args[0]
        filename = args[1]
        
        # Simple grep simulation
        if "error" in pattern.lower():
            return "Jan 15 14:25:33 corptech-server apache2[456]: [error] File does not exist: /var/www/html/favicon.ico\n", 0
        else:
            return "", 1
    
    def _cmd_tail(self, args: List[str]) -> Tuple[str, int]:
        """Simulate tail command"""
        if not args:
            return "tail: missing operand\n", 1
        
        filename = args[-1]  # Last argument is usually the filename
        
        if filename.startswith("/"):
            filepath = filename
        else:
            filepath = os.path.join(self.current_directory, filename)
        
        file_obj = self.filesystem.get_file(filepath)
        if file_obj and file_obj.content:
            lines = file_obj.content.split('\n')
            # Return last 10 lines (or all if fewer than 10)
            tail_lines = lines[-10:] if len(lines) > 10 else lines
            return "\n".join(tail_lines) + "\n", 0
        else:
            return f"tail: cannot open '{filename}' for reading: No such file or directory\n", 1
    
    def _cmd_head(self, args: List[str]) -> Tuple[str, int]:
        """Simulate head command"""
        if not args:
            return "head: missing operand\n", 1
        
        filename = args[-1]  # Last argument is usually the filename
        
        if filename.startswith("/"):
            filepath = filename
        else:
            filepath = os.path.join(self.current_directory, filename)
        
        file_obj = self.filesystem.get_file(filepath)
        if file_obj and file_obj.content:
            lines = file_obj.content.split('\n')
            # Return first 10 lines (or all if fewer than 10)
            head_lines = lines[:10] if len(lines) > 10 else lines
            return "\n".join(head_lines) + "\n", 0
        else:
            return f"head: cannot open '{filename}' for reading: No such file or directory\n", 1

class SSHHoneypotServer(asyncssh.SSHServer):
    """SSH Server implementation for the honeypot"""
    
    def __init__(self):
        self.filesystem = SyntheticFileSystem()
        self.sessions: Dict[str, SSHSession] = {}
        
        # Synthetic credentials
        self.credentials = {
            "admin": "admin123",
            "root": "toor",
            "user": "password",
            "test": "test123",
            "backup": "backup"
        }
    
    def connection_made(self, conn):
        """Called when a connection is established"""
        self.conn = conn
        logger.info(f"SSH connection from {conn.get_extra_info('peername')}")
    
    def connection_lost(self, exc):
        """Called when connection is lost"""
        logger.info("SSH connection closed")
    
    def begin_auth(self, username):
        """Begin authentication process"""
        return True
    
    def password_auth_supported(self):
        """Enable password authentication"""
        return True
    
    def validate_password(self, username, password):
        """Validate password authentication"""
        session_id = str(uuid.uuid4())
        
        # Log authentication attempt
        logger.info(f"SSH auth attempt: {username}:{password}", extra={
            "session_id": session_id,
            "username": username,
            "password": password,
            "synthetic": True
        })
        
        # Check synthetic credentials
        if username in self.credentials and self.credentials[username] == password:
            # Create session
            self.sessions[session_id] = SSHSession(
                session_id=session_id,
                username=username,
                ip_address=self.conn.get_extra_info('peername')[0],
                start_time=datetime.now(),
                last_activity=datetime.now(),
                commands=[],
                working_directory="/home/admin" if username == "admin" else f"/home/{username}",
                environment={}
            )
            
            logger.info(f"SSH auth success: {username}", extra={
                "session_id": session_id,
                "username": username,
                "synthetic": True
            })
            return True
        
        logger.info(f"SSH auth failed: {username}", extra={
            "session_id": session_id,
            "username": username,
            "synthetic": True
        })
        return False
    
    def session_requested(self):
        """Handle session request"""
        return SSHHoneypotSession(self.filesystem, self.sessions)

class SSHHoneypotSession(SSHServerSession):
    """SSH session handler"""
    
    def __init__(self, filesystem: SyntheticFileSystem, sessions: Dict[str, SSHSession]):
        self.filesystem = filesystem
        self.sessions = sessions
        self.session_id = None
        self.command_simulator = None
    
    def connection_made(self, chan):
        """Called when session channel is created"""
        self.chan = chan
        
        # Find our session
        for session_id, session in self.sessions.items():
            if session.ip_address == chan.get_extra_info('peername')[0]:
                self.session_id = session_id
                self.command_simulator = CommandSimulator(self.filesystem)
                break
    
    def shell_requested(self):
        """Handle shell request"""
        return SSHHoneypotProcess(self.filesystem, self.sessions, self.session_id)
    
    def exec_requested(self, command):
        """Handle command execution request"""
        return SSHHoneypotProcess(self.filesystem, self.sessions, self.session_id, command)

class SSHHoneypotProcess(SSHServerProcess):
    """SSH process handler for command execution"""
    
    def __init__(self, filesystem: SyntheticFileSystem, sessions: Dict[str, SSHSession], session_id: str, command: str = None):
        self.filesystem = filesystem
        self.sessions = sessions
        self.session_id = session_id
        self.command = command
        self.command_simulator = CommandSimulator(filesystem)
        
    def connection_made(self, proc):
        """Called when process is created"""
        self.proc = proc
        
        if self.command:
            # Execute single command
            self._execute_command(self.command)
            self.proc.exit(0)
        else:
            # Interactive shell
            self._send_prompt()
    
    def data_received(self, data, datatype):
        """Handle incoming data"""
        if datatype == asyncssh.EXTENDED_DATA_STDERR:
            return
        
        try:
            command_line = data.decode('utf-8').strip()
            if command_line:
                self._execute_command(command_line)
            self._send_prompt()
        except Exception as e:
            logger.error(f"Error processing command: {e}")
            self.proc.stdout.write(f"Error: {e}\n")
            self._send_prompt()
    
    def _execute_command(self, command_line: str):
        """Execute a command and send response"""
        if not command_line.strip():
            return
        
        # Parse command
        parts = command_line.strip().split()
        if not parts:
            return
        
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        # Log command execution
        if self.session_id and self.session_id in self.sessions:
            session = self.sessions[self.session_id]
            session.last_activity = datetime.now()
            
            cmd_exec = CommandExecution(
                command=command,
                args=args,
                timestamp=datetime.now(),
                session_id=self.session_id,
                user=session.username,
                working_directory=self.command_simulator.current_directory,
                exit_code=0,
                output="",
                synthetic=True
            )
            
            session.commands.append(cmd_exec)
        
        # Handle special commands
        if command == "exit" or command == "logout":
            self.proc.stdout.write("logout\n")
            self.proc.exit(0)
            return
        
        # Execute command
        try:
            output, exit_code = self.command_simulator.execute_command(command, args)
            self.proc.stdout.write(output)
            
            # Update command execution record
            if self.session_id and self.session_id in self.sessions:
                session = self.sessions[self.session_id]
                if session.commands:
                    session.commands[-1].output = output
                    session.commands[-1].exit_code = exit_code
            
            logger.info(f"SSH command executed: {command_line}", extra={
                "session_id": self.session_id,
                "command": command,
                "args": args,
                "exit_code": exit_code,
                "synthetic": True
            })
            
        except Exception as e:
            error_msg = f"bash: {command}: command error\n"
            self.proc.stdout.write(error_msg)
            logger.error(f"Command execution error: {e}")
    
    def _send_prompt(self):
        """Send shell prompt"""
        if self.session_id and self.session_id in self.sessions:
            session = self.sessions[self.session_id]
            username = session.username
            hostname = "corptech-server"
            current_dir = self.command_simulator.current_directory
            
            # Simplify path for prompt
            if current_dir == f"/home/{username}":
                current_dir = "~"
            elif current_dir.startswith(f"/home/{username}/"):
                current_dir = "~" + current_dir[len(f"/home/{username}"):]
            
            prompt = f"{username}@{hostname}:{current_dir}$ "
            self.proc.stdout.write(prompt)

class SSHHoneypot:
    """Main SSH Honeypot class"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 2222):
        self.host = host
        self.port = port
        self.server = None
        self.server_instance = SSHHoneypotServer()
    
    async def start(self):
        """Start the SSH honeypot server"""
        try:
            # Generate host key if it doesn't exist
            host_key_path = "ssh_host_key"
            if not os.path.exists(host_key_path):
                # Generate a temporary host key
                key = asyncssh.generate_private_key('ssh-rsa', key_size=2048)
                key.write_private_key(host_key_path)
            
            self.server = await asyncssh.create_server(
                lambda: self.server_instance,
                host=self.host,
                port=self.port,
                server_host_keys=[host_key_path],
                process_factory=None
            )
            
            logger.info(f"SSH Honeypot started on {self.host}:{self.port}")
            
        except Exception as e:
            logger.error(f"Failed to start SSH honeypot: {e}")
            raise
    
    async def stop(self):
        """Stop the SSH honeypot server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("SSH Honeypot stopped")
    
    def get_sessions(self) -> Dict[str, SSHSession]:
        """Get all session data for intelligence analysis"""
        return self.server_instance.sessions

if __name__ == "__main__":
    # Example usage
    async def main():
        honeypot = SSHHoneypot()
        await honeypot.start()
        
        try:
            # Keep running
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await honeypot.stop()
    
    asyncio.run(main())