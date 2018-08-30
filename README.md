# arp-spoofing
Linux ARP reply sending, relay, recovery. ( ARP spoofing )

### libpcap
#### pcap_live_open()
3번째 인자는 read time out.  
컨텍스트 스위칭 오버헤드를 줄이기 위해 read time 동안은 패킷을 받아도 깨어나지 않다가,  
timeout 시 깨어나면서 받았던 패킷을 한 번에 처리한다.  
1로 설정하면 패킷을 받는 즉시 처리하게 된다.  
-1로 설정하면 패킷을 받지 않아도 깨어나 CPU 로드율이 100이 된다.  
