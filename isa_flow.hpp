#ifndef __ISA_FLOW_HPP__
#define __ISA_FLOW_HPP__

#include <tuple>
#include <map>
#include "isa_classes.hpp"
#define flowToBitsetPrepare() uint bitset_offset = 0; std::bitset<NETFLOW_V5_DATASIZE> bitset_array
#define flowToBitset(data) bitsetToBitset(&bitset_array, data, &bitset_offset)

/** Header - NetFlow Version 5 **/
struct FlowHeader {
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;

    uint8_t engine_type; // 0
    uint8_t engine_id;   // 0
    uint16_t sampling_interval;  // 0
};

/** Record - NetFlow Version 5 **/
struct FlowRecord {
    uint32_t srcaddr;
    uint32_t dstaddr;

    uint32_t nexthop;    // 0
    uint16_t input;      // 0
    uint16_t output;     // 0

    uint32_t dPkts;
    uint32_t dOctets;
    uint32_t First;
    uint32_t Last;
    uint16_t srcport;
    uint16_t dstport;

    uint8_t pad1;        // 0

    uint8_t tcp_flags;
    uint8_t prot;
    uint8_t tos;

    uint16_t src_as;     // 0
    uint16_t dst_as;     // 0
    uint8_t src_mask;    // 0
    uint8_t dst_mask;    // 0
    uint16_t pad2;       // 0
};

/** Flow structure **/
struct Flow {
    struct FlowHeader* header;
    struct FlowRecord* record;
};

// new flow header with (default) values
struct FlowHeader* createFlowHeader(uint32_t SysUptime, uint32_t flow_sequence, struct timeval c_time);

// new flow record with (default) values
struct FlowRecord* createFlowRecord(std::tuple<in_addr, in_addr, pcap_port, pcap_port, protocol, tos> pFlow, uint32_t dOctets, uint32_t SysUptime, uint8_t tcp_flags);

// new flow structure
struct Flow* createFlow (struct FlowHeader* header, struct FlowRecord* record);

// loads Flow structure in bit format into given array
void loadFlowToBytes(uint8_t* data_array, struct Flow* flow_struct);

void flowPrintStatsPacket(statistics* programStats);

void flowPrintStatsHeader();

void flowUpdateTime(data* programData);

bool isFlowInCache(struct Flow** flow, std::map<uint, struct Flow*> flowCache, std::tuple<in_addr, in_addr, pcap_port, pcap_port, protocol, tos> data);

void flowPrintStats(struct FlowHeader* flow_header, struct FlowRecord* flow_record, char* src_ip, char* dst_ip);

void flowPrintStatsBegin(struct FlowHeader* flow_header, bool newFlow);

void updateFlow(struct Flow** flow, data* programData, statistics* programStats);

void createFlow(struct Flow** flow, std::map<uint, struct Flow*>* flowCache, data* programData, statistics* programStats, std::tuple<in_addr, in_addr, pcap_port, pcap_port, protocol, tos> data);

#endif