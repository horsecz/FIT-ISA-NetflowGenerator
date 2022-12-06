#include "isa.hpp"
#include "isa_classes.hpp"
#include "isa_collector.hpp"
#include "isa_flow.hpp"
#include "isa_argparse.hpp"
#include "isa_flowexport.hpp"
#include "isa_utility.hpp"

/** core program function (collecting packets, working with flows and exporting them) **/
int collectAndExport(data* programData, statistics* programStats) {
    struct pcap_pkthdr header;      // packet header
    struct Flow* flow;              // current flow
    pcap_t *handle = NULL;          // pcap session
    std::map<uint, struct Flow*> flowCache;     // flow-cache
    std::tuple<in_addr, in_addr, pcap_port, pcap_port, protocol, tos> data;     // current flow data
    int result = 0;

    if ((result = preparePcap(programData, &handle)))
        return result;
    
    if (ISA_VERBOSE_PRINT)
        flowPrintStatsHeader();

    result = openUDPSocket(programData);
    if (result)
        programData->udp_error = true;

    while ((programData->packet = pcap_next(handle, &header))) {
        programStats->newPacket();
        if (ISA_VERBOSE_PRINT)
            flowPrintStatsPacket(programStats);
        
        // zero array, load new packet
        udpDataReset(programData->udp_data_send);        
        result = loadPcapHeaders(programData);
        if (result == ISA_RETURN_PCAPHEADER)
            continue;
        if (getProtocolData(programData))
            continue;

        getIPStrings(programData);
        data = std::make_tuple(programData->ip->ip_src, programData->ip->ip_dst, programData->src_port, programData->dst_port, programData->ip_protocol, programData->ip_tos);

        // export flows (timers and flags)
        exportActiveFlows(&flowCache, programData, programStats);
        exportInactiveFlows(&flowCache, programData, programStats);
        exportTCPFlows(&flowCache, programData, programStats);

        // update time
        programData->c_time = header.ts;
        flowUpdateTime(programData);

        // create new flow or update existing
        if (isFlowInCache(&flow, flowCache, data))
            updateFlow(&flow, programData, programStats);
        else
            createFlow(&flow, &flowCache, programData, programStats, data);

        // export flow(s) if flow-cache is greater than maximum size
        exportOverflowFlows(&flowCache, programData, programStats);
    }

    // close PCAP file, export all flows in cache (and print stats)
    pcap_close(handle);
    exportRemainingFlows(&flowCache, programData, programStats);
    if (ISA_VERBOSE_PRINT)
        programStats->printStatistics();

    if (result == ISA_RETURN_OK)
        closeUDPSocket(programData);
    return result;
}


int main(int argc, char *argv[]) {
    statistics* programStats = new statistics();
    data* programData = new data();

    // Parse program arguments and load them into class
    programArguments p;
    bool result = p.load(argc, argv);
    if (!result) {
        std::cerr << "Wrong command syntax. Try '-h' parameter for help.\n";
        return ISA_RETURN_ARGERR;
    }

    // If argument help is present, print it and exit
    if (argparse_isHelpActive(p))
        return ISA_RETURN_OK;

    // Check collector argument
    if (!argparse_collector(p, programData->clt))
        return ISA_RETURN_ARGERR;

    // Check numerical arguments, store them if present and correct
    if (!argparse_checkNumericalValues(p, &(programData->activeTimer), &programData->inactiveTimer, &(programData->flowCacheSize)))
        return ISA_RETURN_ARGERR;

    // Print argument values if verbose printing is set
    if (ISA_VERBOSE_PRINT)
        argparse_printReport(p, programData->clt, programData->activeTimer, programData->inactiveTimer, programData->flowCacheSize);

    // Set file (or stdin) path
    argparse_setFile(p, programData);

    // Do the job
    loadUDPAddress(programData);
    prepareFile(programData);
    int returnResult = collectAndExport(programData, programStats);
    if (returnResult || programData->udp_error) {
        std::cerr << "Program ended with code " << std::to_string((returnResult ? returnResult : programData->udp_error_v)) << ". ("<< programData->udp_error_str << ")\n";
        return returnResult;
    }
    
    return ISA_RETURN_OK;
}
