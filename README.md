
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

