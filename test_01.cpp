#include <iostream>
#include <cstring>
#include <pcap/pcap.h>
#include <fstream>
#include <cmath>
#include <iomanip>
#include <bitset>
#include <cctype> // ctype.h

#include "utils.h"

using namespace std;


// build for windows: (workn't)
// x86_64-w64-mingw32-g++ -static -static-libgcc -static-libstdc++ -o test_01.exe test_01.cpp -lws2_32 -lwinmm -lwpcap -L/Downloads/npcap-sdk-1.13/Lib -I/Downloads/npcap-sdk-1.13/Include

// build for linux:
// g++ test_01.cpp -o test_01 -lpcap



int findDeviceName (pcap_if_t *&selected_device, pcap_if_t *&returndevs);
void print_packet_hex(const u_char *packet, int len);

int main(int argc, char *argv[]) {

    char *port, *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = nullptr; // list of all available network devices
    pcap_if_t *device = nullptr; // selected device to sniff on
    pcap_t *handle = nullptr; // session handle
    char filter_exp[11] = "port "; // filter expression -> only certain port
    struct bpf_program compiled_filter_exp; // compiled filter expression (transformed to be a function parameter)
    bpf_u_int32 dev_netmask; // device's mask
    bpf_u_int32 dev_ipaddr; // device's IP address

    struct pcap_pkthdr packet_header;
    const u_char *packet_data;
    

    if (argc == 1) {
        port = new char[6];
        std::cout << "Please enter the socket number: ";
        cin.getline(port, 5);
    }
    else if (argc == 2) {
        port = argv[1];
    }
    else {
        std::cerr << "Error: Too many input parameters.\n";
        return 1;
    }
    strcat(filter_exp, port);


    if (findDeviceName(device, alldevs) != 0) {
        return 1;
    }

    std::cout << "Selected device: " << device->name << std::endl;  

    if (pcap_lookupnet(device->name, &dev_netmask, &dev_ipaddr, errbuf) == -1) { // get device's mask and ip
        std::cerr << "Couldn't open device " << device->name << ": " << errbuf << std::endl;
        return 2;
    }

    handle = pcap_open_live(device->name, 65535, 0, 1000, errbuf); // open the device
    if (handle == nullptr) {
        std::cerr << "Error: Couldn't open device " << device->name << ": " << errbuf << std::endl;
        return 2;
    }

    if (pcap_compile(handle, &compiled_filter_exp, filter_exp, 0, dev_netmask) == -1) { // compile the filter expression
        std::cerr << "Coudn't parse filter " << filter_exp << ": " << errbuf << std::endl;
        return 2;
    }
    if (pcap_setfilter(handle, &compiled_filter_exp) == -1) { // apply the compiled filter
        std::cerr << "Coudn't parse filter " << filter_exp << ": " << errbuf << std::endl;
        return 2;
    }

    std::cout << "Waiting for a packet to capture...\n";

    // grab the next packet
    packet_data = pcap_next(handle, &packet_header);
    std::cout << "\nLength of the captured part of packet " << packet_header.caplen << std::endl;
    std::cout << "Length of the entire packet: " << packet_header.len << std::endl;
    std::cout << "Packet time stamp (UTC+0): ";
    printf("%02d:%02d:%02d\n", (int)(packet_header.ts.tv_sec / 3600) % 24, int(packet_header.ts.tv_sec % 3600) / 60, (int)packet_header.ts.tv_sec % 60);
    std::cout << "Dumping packet data:\n"/* << packet_data << std::endl*/;
    print_packet_hex(packet_data, packet_header.len);

    pcap_freealldevs(alldevs);
    
    return 0;
}

int findDeviceName (pcap_if_t *&selected_device, pcap_if_t *&returndevs) {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    selected_device = nullptr;

    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return ERR_FINDING_DEVS;
    }

    // iterate through the list of devices
    for (device = alldevs; device != nullptr; device = device->next) {
        // skip loopback devices
        if(device->flags & PCAP_IF_LOOPBACK) {
            continue;
        }

        // check if the device has an address
        if (device->addresses != nullptr) {
            selected_device = device;
            break;
        }
    }

    //pcap_freealldevs(alldevs);
    returndevs = alldevs;

    if (selected_device == nullptr) {
        std::cerr << "No suitable device found.\n";
        return ERR_NO_SUITABLE_DEV; 
    }

    return 0;
}

void print_packet_hex(const u_char *packet, int len) {
    
    int num_of_bits = ceil(log2(len / 16.0f));
    for (int i = 0; i < num_of_bits; i++) {
        printf(" ");
    }

    // draw upper border
    printf(" \u250C");
    for (int i = 0; i < 69; i++) {
        if (i == 50)
            printf("\u252c");
        else printf("\u2500");
    }
    printf("\u2510\n");

    // PRINT PACKET DATA
    for (int i = 0; i < len; i += 16) {
        // print row number
        for (int j = num_of_bits - 1; j >= 0; j--) {
            printf("%c", ((i+1) / 16) & (1 << j) ? '1': '0');
        }
        printf(" \u2502 ");

        // print one row (16 bytes hex) at once
        for (int j = 0; j < 16 && (i + j) < len; j++) {
            if (j == 8)
                printf(" ");
            printf("%02x ", packet[i + j]);
        }
        // add spacing if the row isn't full
        for (int j = len - i; j < 16; j++) {
            printf("   ");
        }
        if ((len - i) < 8)
            printf(" ");
        printf("\u2502 ");

        // print decoded row data
        for (int j = 0; j < 16 && (i + j) < len; j++) {
            u_char ch = packet[i + j];
            if (isprint(ch))
                printf("%c", ch);
            else // print "." if the char isn't printable
                printf(".");
        }
        // add spacing if the row isn't full
        for (int j = len - i; j < 16; j++) {
            printf(" ");
        }
        printf(" \u2502\n");
    }

    // draw bottom border
    for (int i = 0; i < num_of_bits; i++) {
        printf(" ");
    }
    printf(" \u2514");
    for (int i = 0; i < 69; i++) {
        if (i == 50)
            printf("\u2534");
        else printf("\u2500");
    }
    printf("\u2518\n");

}