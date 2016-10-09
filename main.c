#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#define CAP_LEN 65535

struct tm *timePoint;
char currentFilename[18];
char packageBuf[30];
time_t nowTime;
FILE *fp;

void getData(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    nowTime = time(NULL);
    timePoint = localtime(&nowTime);
    snprintf(currentFilename, sizeof(currentFilename),  "data/%d%d%d%d.log", 1900 + timePoint->tm_year, timePoint->tm_mon + 1, timePoint->tm_mday, timePoint->tm_hour);
    snprintf(packageBuf, sizeof(packageBuf), "Number of bytes:%d\n", pkthdr->caplen);
    if ((fp = fopen(currentFilename, "a")) != NULL) {
        fwrite(packageBuf, sizeof(packageBuf), 1, fp);
        fclose(fp);
    }
}

int main(int argc, char *argv[]) {

    if (argc != 3) {
        printf("wrong parameter\n");
        exit(1);
    }

    char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
    char rule[20];
    int ruleRes;

    pcap_t *pcapPoint;
    device = argv[1];

    if ((ruleRes = snprintf(rule, sizeof(rule), "dst port %s", argv[2])) < 0) {
        printf("wrong rule\n");
        exit(1);
    }

    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_lookupnet(device, &net, &mask, errbuf);

    pcapPoint = pcap_open_live(device, CAP_LEN, 1, 0, errbuf);
    if (!pcapPoint) {
        printf("error %s\n", errbuf);
        exit(1);
    }

    struct bpf_program filter;
    pcap_compile(pcapPoint, &filter, rule, 1, net);
    pcap_setfilter(pcapPoint, &filter);

    int id = 0;
    pcap_loop(pcapPoint, -1, getData, (u_char*)&id);

    pcap_close(pcapPoint);

    return 0;
}
