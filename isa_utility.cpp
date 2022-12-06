#include "isa_utility.hpp"

void getIPStrings(data* programData) {
    string_ip temp = inet_ntoa(programData->ip->ip_src);
    strcpy(programData->src_ip, temp);
    temp = inet_ntoa(programData->ip->ip_dst);
    strcpy(programData->dst_ip, temp);
}

int getProtocolData(data* programData) {
    programData->ip_protocol = programData->ip->ip_p;
    
    switch (programData->ip->ip_p) {
        case 1: // icmp
            //icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);
            programData->src_port = 0;
            programData->dst_port = 0;
            break;
        case 6: // tcp
            programData->tcp = (struct sniff_tcp*)(programData->packet + SIZE_ETHERNET + programData->size_ip);
                
            programData->src_port = htons(programData->tcp->th_sport);
            programData->dst_port = htons(programData->tcp->th_dport);
            programData->tcp_header = true;
            break;
        case 17: // udp
            programData->udp = (struct sniff_udp*)(programData->packet + SIZE_ETHERNET + programData->size_ip);

            programData->src_port = htons(programData->udp->src_port);
            programData->dst_port = htons(programData->udp->dst_port);
            break;
        default:
            strcpy(programData->udp_error_str, "Some packet(s) used unsupported protocol(s), ignored");
            return ISA_RETURN_PCAPPROTOCOL;
            break;
    }
    return ISA_RETURN_OK;
}

int loadPcapHeaders(data* programData) {
    //eth = (struct sniff_ethernet*)(packet);
    programData->ip = (struct sniff_ip*)(programData->packet + SIZE_ETHERNET);
    programData->size_ip = IP_HL(programData->ip)*4;
    if (programData->size_ip < 20) {
        char s[1024] = "Invalid IP header length: ";
        strcat(s, std::to_string((programData->size_ip)).c_str());
        strcat(s, " bytes\n");
        strcpy(programData->udp_error_str, s);
        return ISA_RETURN_PCAPHEADER;
    }
    return ISA_RETURN_OK;
}

void loadUDPAddress(data* programData) {
    std::string str_addr = ((programData)->clt->getAddress());
    std::string str_port = ((programData)->clt->getPort());
    programData->udp_address = new char[1024];
    programData->udp_port = new char[1024];

    strcpy((programData)->udp_address, str_addr.c_str());
    strcpy((programData)->udp_port, str_port.c_str());
}

int preparePcap(data* programData, pcap_t **handle) {
    // open device
    *handle = pcap_open_offline(programData->filePath, programData->errbuf);
    if (*handle == NULL) {
        char s[1024] = "Unable to open pcap in default device - ";
        strcat(s, programData->errbuf);
        strcpy(programData->udp_error_str, s);
        return ISA_RETURN_NOPCAP;
    }
    //compile and apply filter
    if (pcap_compile(*handle, &(programData->fp), programData->filter_exp, 0, programData->net) == -1) {
	    char s[1024] = "Couldn't parse filter ";
        strcat(s, programData->filter_exp);
        strcat(s, ": ");
        strcat(s, pcap_geterr(*handle));
        strcpy(programData->udp_error_str, s);
	    return ISA_RETURN_FILTERPARSE;
    }
    if (pcap_setfilter(*handle, &(programData->fp)) == -1) {
	    char s[1024] = "Couldn't install filter ";
        strcat(s, programData->filter_exp);
        strcat(s, ": ");
        strcat(s, pcap_geterr(*handle));
        strcpy(programData->udp_error_str, s);
	    return ISA_RETURN_FILTERINSTALL;
    }

    return ISA_RETURN_OK;
}

void prepareFile(data* programData) {
    if (programData->filePath == NULL) {
        programData->filePath = new char[2];
        strcpy(programData->filePath, "-");
    }
}