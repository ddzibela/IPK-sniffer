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

void printPacket(std::string time, std::string addr1, std::string port1,std::string addr2, std::string port2)
{
    std::cout << time << " " << addr1 << " : " << port1 << " > " << addr2 << " : " << port2 << ", length " << std::endl;
    //looop 16 bytes
        //cout << offfset << packet << trimNonPrintable(packet)
}

void gotPacket(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet)
{

    std::cout << header->len << std::endl;
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
    
    
    if (pcap_lookupnet(device.c_str(), &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }
    std::cerr << "creating handle" << std::endl;
    pcap_t *handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    std::cerr << handle << std::endl;
    if(handle == nullptr){
        throw errbuf;
    }
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
    }
    if (pcap_setfilter(handle, &fp) == -1) {
    }
    pcap_loop(handle, 10, &gotPacket, nullptr);
    pcap_close(handle);
}

int main(int argc, char** argv)
{
    //optArgs options = getOpts(argc, argv);
    try{
        getPackets("eth0", " ", 10);
    } catch (const char *error_buffer)
    {
        std::cerr << error_buffer << std::endl;
    }

    try
    {
        listAllDevs();
    }
    catch (const char *error_buffer)
    {
        std::cerr << error_buffer << std::endl;
    }

    return 0;
}