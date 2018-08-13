all: arp-spoofing

arp-spoofing: main.o packet.o sysinfo.o
	g++ -g -o arp-spoofing main.o packet.o sysinfo.o -lpcap

main.o: main.cpp
	g++ -g -c -o main.o main.cpp

packet.o: packet.cpp packet.h
	g++ -g -c -o packet.o packet.cpp

sysinfo.o: sysinfo.cpp sysinfo.h
	g++ -g -c -o sysinfo.o sysinfo.cpp

clean:
	rm -f arp-spoofing
	rm -f *.o

