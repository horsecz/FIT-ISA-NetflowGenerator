#ifndef __ISA_UTILITY_HPP__
#define __ISA_UTILITY_HPP__

#include "isa_classes.hpp"
#define udpDataReset(udp_data_send) memset(udp_data_send, 0, NETFLOW_V5_DATASIZE)

void getIPStrings(data* programData);

int getProtocolData(data* programData);

int loadPcapHeaders(data* programData);

void loadUDPAddress(data* programData);

int preparePcap(data* programData, pcap_t **handle);

void prepareFile(data* programData);

#endif