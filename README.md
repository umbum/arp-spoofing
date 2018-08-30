# arp-spoofing
Linux ARP reply sending, relay, recovery. ( ARP spoofing )

## to-do
- ArpHandler namespace(static class)로 변경할지 결정. <br>
dev, handle, ip, mac은 서로에게 종속적인 값. 
따라서 static으로 지정하거나 namespace로 변경하면 한 프로세스는 하나의 dev밖에 처리하지 못함. 근데 이건 크게 문제되는건 아니다. 
class는 상속이 장점이고, namespace는 static개념이니 공간이 절약된다는 장점이 있다.
근데 또 namespace를 사용하게 되면 sendARPRequest같은 데에서 네임스페이스 내부의 전역 변수 ::handle을 참조하게 될텐데, 이게 썩 자연스러워 보이지 않음. 

- ip, mac 가져오는거 함수에서 처리하기 <br>
함수에서 NULL 이면 resolve하고, 아니면 바로 반환하도록 구성하기. 

### libpcap
#### pcap_live_open()
3번째 인자는 read time out. 
컨텍스트 스위칭 오버헤드를 줄이기 위해 read time 동안은 패킷을 받아도 깨어나지 않다가, 
timeout 시 깨어나면서 받았던 패킷을 한 번에 처리한다. 
1로 설정하면 패킷을 받는 즉시 처리하게 된다.  
-1로 설정하면 패킷을 받지 않아도 깨어나 CPU 로드율이 100이 된다. 
