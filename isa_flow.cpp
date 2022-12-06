#include "isa.hpp"
#include "isa_bitset.hpp"
#include "isa_flow.hpp"

struct FlowHeader* createFlowHeader(uint32_t SysUptime, uint32_t flow_sequence, struct timeval c_time) {
    struct FlowHeader *head = new struct FlowHeader;
    
    head->version = htons((uint16_t) 5);
    head->count = htons((uint16_t) 1);
    head->SysUptime = htonl(SysUptime);        
    head->unix_secs = htonl((uint32_t) c_time.tv_sec);   // var, repepe
    head->unix_nsecs = htonl((uint32_t) c_time.tv_usec * 1000);  // var, repepe
    head->flow_sequence = htonl(flow_sequence);

    head->engine_type = 0;
    head->engine_id = 0;
    head->sampling_interval = 0;

    return head;
}

struct FlowRecord* createFlowRecord(std::tuple<in_addr, in_addr, pcap_port, pcap_port, protocol, tos> pFlow, uint32_t dOctets, uint32_t SysUptime, uint8_t tcp_flags) {
    struct FlowRecord *rec = new struct FlowRecord;
    struct in_addr src = std::get<0>(pFlow);
    struct in_addr dst = std::get<1>(pFlow);
    rec->srcaddr = src.s_addr;
    rec->dstaddr = dst.s_addr;
    
    rec->nexthop = 0;
    rec->input = 0;
    rec->output = 0; 

    rec->dPkts = htonl(1);
    rec->dOctets = htonl(dOctets);
    rec->First = htonl(SysUptime);
    rec->Last = htonl(SysUptime);
    rec->srcport = htons(std::get<2>(pFlow));
    rec->dstport = htons(std::get<3>(pFlow));

    rec->pad1 = 0;

    rec->tcp_flags = tcp_flags;
    rec->prot = std::get<4>(pFlow);
    rec->tos = std::get<5>(pFlow);

    rec->src_as = 0;
    rec->dst_as = 0;
    rec->src_mask = 0;
    rec->dst_mask = 0;
    rec->pad2 = 0;

    return rec;
}

struct Flow* createFlow (struct FlowHeader* header, struct FlowRecord* record) {
    struct Flow* new_flow = new struct Flow;
    new_flow->header = header;
    new_flow->record = record;
    return new_flow;
}

void loadFlowToBytes(uint8_t* data_array, struct Flow* flow_struct) {
    flowToBitsetPrepare();
    flowToBitset(flow_struct->header->version);
    flowToBitset(flow_struct->header->count);
    flowToBitset(flow_struct->header->SysUptime);
    flowToBitset(flow_struct->header->unix_secs);
    flowToBitset(flow_struct->header->unix_nsecs);
    flowToBitset(flow_struct->header->flow_sequence);
    flowToBitset(flow_struct->header->engine_type);
    flowToBitset(flow_struct->header->engine_id);
    flowToBitset(flow_struct->header->sampling_interval);

    flowToBitset(flow_struct->record->srcaddr);
    flowToBitset(flow_struct->record->dstaddr);
    flowToBitset(flow_struct->record->nexthop);
    flowToBitset(flow_struct->record->input);
    flowToBitset(flow_struct->record->output);
    flowToBitset(flow_struct->record->dPkts);
    flowToBitset(flow_struct->record->dOctets);
    flowToBitset(flow_struct->record->First);
    flowToBitset(flow_struct->record->Last);
    flowToBitset(flow_struct->record->srcport);
    flowToBitset(flow_struct->record->dstport);
    flowToBitset(flow_struct->record->pad1);
    flowToBitset(flow_struct->record->tcp_flags);
    flowToBitset(flow_struct->record->prot);
    flowToBitset(flow_struct->record->tos);
    flowToBitset(flow_struct->record->src_as);
    flowToBitset(flow_struct->record->dst_as);
    flowToBitset(flow_struct->record->src_mask);
    flowToBitset(flow_struct->record->dst_mask);
    flowToBitset(flow_struct->record->pad2);

    bitsetToChar(bitset_array, data_array);
}

void flowUpdateTime(data* programData) {
    if (!programData->SysUptime_begin) {
        programData->SysUptime_start = programData->c_time.tv_sec*1000*1000  + programData->c_time.tv_usec;
        if (ISA_VERBOSE_PRINT)
            std::cout << "<<! Received first packet at 'UNIX Time " << std::to_string(programData->SysUptime_start) << "' (microseconds) !>>\n\t";
        programData->SysUptime_begin = true;
    }

    programData->SysUptime_end = programData->c_time.tv_sec*1000*1000 + programData->c_time.tv_usec;
    programData->SysUptime_diff = (programData->SysUptime_end - programData->SysUptime_start);
}

bool isFlowInCache(struct Flow** flow, std::map<uint, struct Flow*> flowCache, std::tuple<in_addr, in_addr, pcap_port, pcap_port, protocol, tos> data) {
    for (std::map<uint , struct Flow*>::iterator it = flowCache.begin(); it != flowCache.end(); it++) {
        struct FlowRecord* r = it->second->record;
        struct in_addr src = std::get<0>(data);
        struct in_addr dst = std::get<1>(data);

        if (r->srcaddr == src.s_addr && r->dstaddr == dst.s_addr) {
            if(ntohs(r->srcport) == std::get<2>(data) && ntohs(r->dstport) == std::get<3>(data)) {
                if(r->prot == std::get<4>(data)) {
                    *flow = it->second;
                    return true;
                }
            }
        }
    }
    return false;
}

void flowPrintStats(struct FlowHeader* flow_header, struct FlowRecord* flow_record, char* src_ip, char* dst_ip) {
    std::cout << std::to_string(ntohl(flow_header->SysUptime)*1000) << "\t\t";
    std::cout << src_ip << ":" << std::to_string(ntohs(flow_record->srcport)) << "\t\t";
    std::cout << dst_ip << ":" << std::to_string(ntohs(flow_record->dstport)) << "\t\t\t";
    std::cout << (flow_record->prot == 1 ? "ICMP" : (flow_record->prot == 6 ? "TCP" : (flow_record->prot == 17 ? "UDP" : std::to_string(flow_record->prot) ) )  ) << "\t\t";
    std::cout << std::to_string(ntohl(flow_record->dOctets)) << "\t";
    std::cout << ( ntohl(flow_record->First) == 0 ? "0000000000" : std::to_string(ntohl(flow_record->First)) )  << "\t";
    std::cout << ( ntohl(flow_record->Last) == 0 ? "0000000000" : std::to_string(ntohl(flow_record->Last)) )  << "\t\t";
    std::cout << std::to_string(flow_record->tcp_flags) << "\t\t";
    std::cout << std::to_string(ntohl(flow_record->dPkts)) << "\t";
    std::cout << "\n";
}

void flowPrintStatsBegin(struct FlowHeader* flow_header, bool newFlow) {
    std::cout << std::to_string(ntohl(flow_header->flow_sequence)) << "\t" << (newFlow ? "create" : "update")  << "\t";
}

void flowPrintStatsPacket(statistics* programStats) {
    std::cout << std::to_string(programStats->packet_counter) << "\t";
}

void flowPrintStatsHeader() {
    std::cout << "packet\tflow\taction\tSysUpTime\t\tsrc\t\t\t\tdst\t\t\t    protocol\t:::\tdOctets\tFirst\t\tLast\t\ttcp_flags\tdPkts\n";
}

void createFlow(struct Flow** flow, std::map<uint, struct Flow*>* flowCache, data* programData, statistics* programStats, std::tuple<in_addr, in_addr, pcap_port, pcap_port, protocol, tos> data) {
    struct FlowHeader* flow_header = createFlowHeader(programData->SysUptime_diff/1000, ++programStats->flow_sequence, programData->c_time); // c_time
    struct FlowRecord* flow_record;
    bool tcp_header = programData->tcp_header;

    if (ISA_VERBOSE_PRINT)
        flowPrintStatsBegin(flow_header, true);
    if (tcp_header)
        flow_record = createFlowRecord(data, (uint32_t) ntohs(programData->ip->ip_len) - programData->size_ip, programData->SysUptime_diff, programData->tcp->th_flags);
    else
        flow_record = createFlowRecord(data, (uint32_t) ntohs(programData->ip->ip_len) - programData->size_ip, programData->SysUptime_diff, 0);
    *flow = createFlow(flow_header, flow_record);

    if (ISA_VERBOSE_PRINT)
        flowPrintStats(flow_header, flow_record, programData->src_ip, programData->dst_ip);

    (*flowCache)[programStats->flow_sequence] = *flow;
    programStats->newFlow();
}

void updateFlow(struct Flow** flow, data* programData, statistics* programStats) {
    struct FlowHeader* flow_header = (*flow)->header;
    struct FlowRecord* flow_record = (*flow)->record;
    bool tcp_header = programData->tcp_header;
            
    if (ISA_VERBOSE_PRINT)
        flowPrintStatsBegin(flow_header, false);

    flow_header->SysUptime = htonl(programData->SysUptime_diff);
    flow_header->unix_secs = htonl(programData->c_time.tv_sec);
    flow_header->unix_nsecs = htonl(programData->c_time.tv_usec * 1000); 
    flow_record->dOctets = htonl((uint32_t) ntohs(programData->ip->ip_len) - programData->size_ip);
    flow_record->Last = flow_header->SysUptime;
    uint32_t dPkts_new = ntohl(flow_record->dPkts);
    flow_record->dPkts = htonl(++dPkts_new);

    if (tcp_header)
        flow_record->tcp_flags |= programData->tcp->th_flags;
    if (ISA_VERBOSE_PRINT)
        flowPrintStats(flow_header, flow_record, programData->src_ip, programData->dst_ip);

    programStats->newFlowUpdate();
}