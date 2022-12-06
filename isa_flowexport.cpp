#include "isa_flowexport.hpp"
#include "isa_flow.hpp"
#include "isa_collector.hpp"

void exportActiveFlows(std::map<uint, struct Flow*>* flowCache, data* programData, statistics* stats)  {
    for (std::map<uint , struct Flow*>::iterator it = flowCache->begin(); it != flowCache->end(); it++) {
        if (ntohl(it->second->record->Last) - ntohl(it->second->record->First) > programData->activeTimer*1000*1000) {
            if (ISA_VERBOSE_PRINT)
                std::cout << std::to_string(it->first) << "\texport\t" << std::to_string(programData->SysUptime_diff) << "\t\t<<! ACTIVE TIMER !>>\n\t";
            loadFlowToBytes(programData->udp_data_send, it->second);
            programData->udp_error_v = exportToCollector(programData);
            flowCache->erase(it->first);
            it = flowCache->begin();
            stats->newExport();
        }
    }
}

void exportInactiveFlows(std::map<uint, struct Flow*>* flowCache, data* programData, statistics* stats)  {
    for (std::map<uint , struct Flow*>::iterator it = flowCache->begin(); it != flowCache->end(); it++) {
        if (programData->SysUptime_diff - ntohl(it->second->record->Last) > programData->inactiveTimer*1000*1000) {
            if (ISA_VERBOSE_PRINT)
                std::cout << std::to_string(it->first) << "\texport\t" << std::to_string(programData->SysUptime_diff) << "\t\t<<! INACTIVE TIMER !>>\n\t";
            loadFlowToBytes(programData->udp_data_send, it->second);
            programData->udp_error_v = exportToCollector(programData);
            flowCache->erase(it->first);
            it = flowCache->begin();
            stats->newExport();
        }
    }
}

void exportTCPFlows(std::map<uint, struct Flow*>* flowCache, data* programData, statistics* stats) {
    if (programData->tcp_header == false || programData->ip_protocol != protocolNumber::TCP)
        return;
    for (std::map<uint , struct Flow*>::iterator it = flowCache->begin(); it != flowCache->end(); it++) {
        if ((it->second->record->tcp_flags & TH_FIN) || (it->second->record->tcp_flags & TH_RST)) {
            if (ISA_VERBOSE_PRINT)
                std::cout << std::to_string(it->first) << "\texport\t" << std::to_string(programData->SysUptime_diff) << "\t\t<<! TCP FLAGS !>>\n\t";
            loadFlowToBytes(programData->udp_data_send, it->second);
            programData->udp_error_v = exportToCollector(programData);
            flowCache->erase(it->first);
            it = flowCache->begin();
            stats->newExport();
        }
    }
}

void exportRemainingFlows(std::map<uint, struct Flow*>* flowCache, data* programData, statistics* stats) {
    if (flowCache->size() && ISA_VERBOSE_PRINT)
        std::cout << "\t<<! Received last packet and cache contains " << std::to_string(flowCache->size()) << " flows - exporting the rest ... !>>\n";

    std::map<uint, struct Flow*>::iterator cache_removal;
    while (flowCache->size() != 0) {
        cache_removal = flowCache->begin();
        loadFlowToBytes(programData->udp_data_send, cache_removal->second);
        programData->udp_error_v = exportToCollector(programData);
        flowCache->erase(cache_removal);
        stats->newExport();
    }
}

void exportOverflowFlows(std::map<uint, struct Flow*>* flowCache, data* programData, statistics* stats) {
    while (flowCache->size() > programData->flowCacheSize) {
            std::map<uint, struct Flow*>::iterator cache_removal = flowCache->begin();
            if (ISA_VERBOSE_PRINT)
                std::cout << "\t" << std::to_string(cache_removal->first) << "\texport\t" << std::to_string(programData->SysUptime_diff) << "\t\t<<! CACHE FULL !>>\n";
            loadFlowToBytes(programData->udp_data_send, cache_removal->second);
            programData->udp_error_v = exportToCollector(programData);
            flowCache->erase(cache_removal);
            stats->newExport();
        }
}