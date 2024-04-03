#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // 이더넷 헤더, IP 헤더, TCP 헤더 포인터 선언
    const struct ether_header *eth_header;
    const struct ip *ip_header;
    const struct tcphdr *tcp_header;
    int ip_header_length, tcp_header_length, payload_length;
    const u_char *payload;

    // 이더넷 헤더 분석
    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        // IP 헤더 길이 계산 (IHL 필드는 32비트 워드 단위)
        ip_header_length = ip_header->ip_hl * 4;

        if (ip_header->ip_p == IPPROTO_TCP) {
            tcp_header = (struct tcphdr*)((u_char*)ip_header + ip_header_length);

            // TCP 헤더 길이 계산 (Data Offset 필드는 32비트 워드 단위)
            tcp_header_length = (tcp_header->th_off) * 4;

            // 페이로드 시작 위치 및 길이 계산
            payload = (u_char*)tcp_header + tcp_header_length;
            payload_length = pkthdr->len - (sizeof(struct ether_header) + ip_header_length + tcp_header_length);

            // 필요한 정보 출력
            printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x, Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
                   eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5],
                   eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
                   eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

            printf("Src IP: %s, Dst IP: %s\n", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
            printf("Src Port: %d, Dst Port: %d\n", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));

            // 페이로드 출력
            if (payload_length > 0) {
                printf("Payload (%d bytes):\n", payload_length);
                for (int i = 0; i < payload_length; i++) {
                    printf("%02x ", payload[i]);
                    if ((i + 1) % 16 == 0) printf("\n");
                }
                printf("\n");
            } else {
                printf("No Payload\n");
            }
        }
    }
}

int main() {
    pcap_if_t *alldevsp, *device;
    char errbuf[PCAP_ERRBUF_SIZE], *dev;
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // 사용할 네트워크 장치 찾기
    if (pcap_findalldevs(&alldevsp, errbuf)) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    // 첫 번째 네트워크 장치 사용
    device = alldevsp;
    if (device == NULL) {
        fprintf(stderr, "No devices found.\n");
        return 2;
    }
    dev = device->name;

    printf("Using device %s\n", dev);

    // 장치 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(2);
    }

    // 네트워크 디바이스의 네트워크 번호와 마스크 얻기
    if (pcap_lookupnet(dev, &net, &net, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
    }

    // 필터 표현식 컴파일
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(2);
    }

    // 필터 설정
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(2);
    }

    // 패킷 캡처 시작 - 무한 루프로 각 패킷마다 packet_handler 콜백 함수 호출
    pcap_loop(handle, 0, packet_handler, NULL);

    // 종료 시 리소스 정리
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(alldevsp);

    printf("Capture complete.\n");
    return 0;
}
