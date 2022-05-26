
```diff
+ green color text
- red color text
```

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
 
![image](https://user-images.githubusercontent.com/96654161/170466825-f9745641-b673-415d-8549-8d974b3251d9.png)
  - info auxiliary/scanner/smb/smb_ms17_010

![image](https://user-images.githubusercontent.com/96654161/170468777-31bd8a4c-e86d-4584-a37c-e2f938d267c9.png)

+ use auxiliary/scanner/smb/smb_ms17_010
+ options 查看設置 ->required 如果是yes就必須要配置
![image](https://user-images.githubusercontent.com/96654161/170471161-04096171-0096-4c96-92e6-fc5cc911859c.png)

+ set RHOSTS 掃描主機IP
+ run / exploit 執行
![image](https://user-images.githubusercontent.com/96654161/170472589-93bc1135-7785-47a5-b28e-c4e3d361b9fe.png)
