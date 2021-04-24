#include <iostream>
#include <pcap/pcap.h>
#include <string.h>

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



int main()
{
    try{
        listAllDevs();
    } catch (const char *error_buffer) {
        std::cerr << error_buffer << std::endl;
    }

    return 0;
}