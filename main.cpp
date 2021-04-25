/**
 * @author Denis Dzibela xdzibe00 
 * @date 2021-04-24
 * @brief A simple packet sniffer.
*/
#include <iostream>
#include <string.h>
#include <iterator>
#include <getopt.h>

#include "headers.h"
#include "protocols.h"

#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <pcap/sll.h>
#include <net/ethernet.h>

struct optArgs{
    std::string interface;
    std::string protocol;
    int port;
    int num;
    optArgs() 
        : port(-1)
        , num(1)
    {}
};

optArgs getOpts(int argc, char** argv)
{
    optArgs options;

    return options;
}

/**
 * @brief Prints a list of all network devices discovered by pcap to standart output.
 * @throw <char* errbuf> If pcap_findalldevs() fails.
 */
void listAllDevs()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t **alldevs;
    auto result = pcap_findalldevs(alldevs, error_buffer);
    if(result == PCAP_ERROR){
        throw error_buffer;
    }

    std::cout << "Listing all network devices: " << std::endl;
    
    if (alldevs == nullptr){
        std::cout << "No network devices were found." << std::endl;
    }

    pcap_if_t *device = *alldevs;
    while (device != nullptr){
        std::cout << "    " << device->name << std::endl;
        device = device->next;
    }
}


/**
 * @brief replaces non printable ASCII chars with '.'
 * @note multi byte chars will lead to multiple '.'
 */
std::string trimNonPrintable(std::string str)
{
    std::string::iterator it;
    for (it = str.begin(); it != str.end(); it++){
        if(*it < 32 || *it > 126){
            *it = '.';
        }
    }
    return str;
}

void printPacket()
{
    //looop 16 bytes
        //cout << offfset << packet << trimNonPrintable(packet)
}

void processIPpacket(int offset, const struct pcap_pkthdr *header, const u_char *packet)
{
    char sip[16], dip[16]; //source and dest IP addr
    int sport{0}, dport{0}; //source and dest port
    auto ip = (struct sniff_ip*)(packet + offset);
    int ip_len = ntohs(ip->ip_len) * 4;

    //obtain human readable IP address representation
    inet_ntop(AF_INET, &(ip->ip_src), sip, sizeof(sip));
    inet_ntop(AF_INET, &(ip->ip_dst), sip, sizeof(dip));

    //obtain port numbers
    switch (ntohs(ip->ip_p))
    {
    case prot_ICMP:{
        break;
    }
    case prot_TCP:{
        auto tcp = (struct sniff_tcp*)(packet + offset + ip_len);
        sport = ntohs(tcp->th_sport);
        dport = ntohs(tcp->th_dport);
        break;
    }
    case prot_UDP:{
        auto udp = (struct sniff_udp*)(packet + offset + ip_len);
        sport = ntohs(udp->ud_sport);
        dport = ntohs(udp->ud_dport);
        break;
    }
    default:
        break;
    }
}

void processIPv6packet(const struct pcap_pkthdr *header, const u_char *packet)
{

}

void processARPpacket(const struct pcap_pkthdr *header, const u_char *packet)
{
    
}

void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    
    //this should never happen
    if(args == nullptr){
        return;
    }
    //standard ethernet
    if(*args == DLT_EN10MB){
        auto ethernet = (struct sniff_ethernet *)(packet);
        switch(ntohs(ethernet->ether_type))
        {
        case ETHERTYPE_IP:
            processIPpacket(SIZE_ETHERNET, header, packet);
            break;
        case ETHERTYPE_IPV6:
            processIPv6packet(header, packet);
            break;
        case ETHERTYPE_ARP:
            processARPpacket(header, packet);
            break;
        default:
            break;
        }
    }
    //linux SLL for "any" device
    if(*args == DLT_LINUX_SLL){

    }



}

/**
 * @brief uses pcap_loop() to sniff desired packets specified by filter settings
 * @arg device network device to be sniffed on
 * @arg filter filter settings for pcap filtr
 * @arg num number of packets to sniff
 */
void getPackets(std::string device, char* filter, int num)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;		/* The compiled filter expression */
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */
    
    //we need the network address to attach our packet filter
    if (pcap_lookupnet(device.c_str(), &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }
    //open a pcap handle
    pcap_t *handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if(handle == nullptr){
        throw errbuf;
    }
    //compile and attach the filter
    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    {
        pcap_perror(handle, "");
        throw 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        pcap_perror(handle, "");
        throw 1;
    }
    //capture packets
    unsigned char linktype = pcap_datalink(handle);
    pcap_loop(handle, 10, &gotPacket, &linktype);
    pcap_close(handle);
}

int main(int argc, char** argv)
{
    //optArgs options = getOpts(argc, argv);
    try{
        getPackets("eth0", "", 10);
    } catch (const char *error_buffer)
    {   

        std::cerr << "ERROR: " << error_buffer << std::endl;
        return 2;
    }
/*
    try
    {
        listAllDevs();
    }
    catch (const char *error_buffer)
    {
        std::cerr << error_buffer << std::endl;
    }
*/
    return 0;

}