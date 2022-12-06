#ifndef __ISA_CLASSES_HPP__
#define __ISA_CLASSES_HPP__

#include "isa.hpp"

/** Datatype of variable **/
enum variableType {
    STRING,
    INT,
    BOOL,
    CHAR,
    FLOAT,
    DOUBLE
};

/** single argument in command line **/
class argument {
    public:
        variableType type;
        std::string arg;
        bool active;

        // Datatype of argument
        void setType(variableType t) {
            this->type = t;
        }

        // Sets content of argument
        // (used only when active - detected in cmd-line command)
        void setArg(std::string a) {
            this->arg = a;
            active = true;
        }

        // Default value for argument
        // (used only in the beginning and once)
        void setDefault(std::string s) {
            this->arg = s;
            active = false;
        }

        // Returns argument content 
        std::string getArg() { return this->arg; }

        // Has been argument used in cmd-line or not?
        bool isActive() { return active; }
    
};

/** processing command line arguments **/
class programArguments {
    public:
        argument File;
        argument NetflowCollector;
        argument ActiveTimer;
        argument InactiveTimer;
        argument FlowCache;
        argument Help;
        int error = 0;

        // For identificating arguments
        enum id {
            FILE,
            NETFLOWCOLLECTOR,
            ACTIVETIMER,
            INACTIVETIMER,
            FLOWCACHE,
            HELP
        };

        // Default values for some arguments
        struct {
            const std::string Collector = "127.0.0.1:2055";
            const std::string ActiveSeconds = "60";
            const std::string InactiveSeconds = "10";
            const std::string FlowSize = "1024";
        } defaultValues;

        // Constructor creates new arguments and sets them to their default values
        programArguments() {
            File.setType(variableType::STRING);
            File.setDefault("none");
            NetflowCollector.setType(variableType::STRING);
            NetflowCollector.setDefault(defaultValues.Collector);
            ActiveTimer.setType(variableType::INT);
            ActiveTimer.setDefault(defaultValues.ActiveSeconds);
            InactiveTimer.setType(variableType::INT);
            InactiveTimer.setDefault(defaultValues.InactiveSeconds);
            FlowCache.setType(variableType::INT);
            FlowCache.setDefault(defaultValues.FlowSize);
            Help.setType(variableType::STRING);
            Help.setDefault("ISA Project: NetFlow data generator\n\
NetFlow exporter, which creates PCAP NetFlow records from catched network data, which will be sent to collector then. \n\
\n\
Syntax: ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>] \n\
  -f <filename>     analyze specified file (default: stdin) \n\
  -c <ip[:port]>    NetFlow collector's IP or hostname and port (default: 127.0.0.1:2055) \n\
  -a <seconds>      interval in 'seconds', when active records will be exported to collector (default: 60) \n\
  -i <seconds>      inactive records will be exported to collector every 'seconds' seconds (default: 10) \n\
  -m <size>         maximum size of flow-cache (default: 1024)\n\
                        (when reached, oldest record will be exported from flow-cache to collector) \n\
\n\
No parameters are required. If some parameter is missing, default value will be used instead. \n\
");
        }

        // Loads and parses arguments into this class via getopt
        bool load(int argc, char *argv[]) {
            int opt = 0;
            opterr = 0;

            while ( (opt = getopt(argc, argv, ":f:c:a:i:m:h")) != -1 ) {
                switch (opt) {
                    case 'f':
                        File.setArg(optarg);
                        break;
                    case 'c':
                        NetflowCollector.setArg(optarg);
                        break;
                    case 'a':
                        ActiveTimer.setArg(optarg);
                        break;
                    case 'i':
                        InactiveTimer.setArg(optarg);
                        break;
                    case 'm':
                        FlowCache.setArg(optarg);
                        break;
                    case 'h':
                        Help.active = true;
                        break;
                    case '?':
                    default:
                        this->error = opterr;
                        return false;
                        break;
                }
            }
            return true;
        }

        int getoptError() { return this->error; }

        // Checks if argument was used in cmd-line or not
        bool isArgumentActive(id arg) {
            switch (arg) {
                case id::FILE:
                    return this->File.isActive();
                case id::NETFLOWCOLLECTOR:
                    return this->NetflowCollector.isActive();
                case id::ACTIVETIMER:
                    return this->ActiveTimer.isActive();
                case id::INACTIVETIMER:
                    return this->InactiveTimer.isActive();
                case id::FLOWCACHE:
                    return this->FlowCache.isActive();
                case id::HELP:
                    return this->Help.isActive();
            }
            return false;
        }

        // Returns content of 'arg' argument (identified by enum) 
        std::string getArgumentParameter(id arg) {
            switch (arg) {
                case id::FILE:
                    return this->File.getArg();
                case id::NETFLOWCOLLECTOR:
                    return this->NetflowCollector.getArg();
                case id::ACTIVETIMER:
                    return this->ActiveTimer.getArg();
                case id::INACTIVETIMER:
                    return this->InactiveTimer.getArg();
                case id::FLOWCACHE:
                    return this->FlowCache.getArg();
                case id::HELP:
                    return this->Help.getArg();
            }
            return NULL;
        }



    // Conversion: String -> Int
    private:
        std::string returnString(std::string s) { return s; }

        int returnInt(std::string s) {
            return stoi(s);
        }

};

/** collector information from cmd-line / argument parsing **/
class collector {
    public:
        std::string address;
        std::string port;
        bool isIP;

        void setAddress (std::string a) { this->address = a; }
        std::string getAddress () { return this->address; }
    
        void setPort (std::string p) { this->port = p; }
        std::string getPort () { return this->port; }

        bool isHostIP() { return this->isIP; }
        void setHostIP(bool x) { this->isIP = x; } 

        std::pair<std::string, std::string> parseCollectorString(std::string c) {
            std::string host = c.substr(0, c.find(":"));
            std::string port = c.substr(c.find(":")+1, c.size());
            if (host == port) {
                port = "2055";
            }
            return std::make_pair(host, port);
        }
};

class statistics {
    public:
        uint flow_export_counter;
        uint flow_counter;
        uint packet_counter;
        uint flow_update_counter;
        uint flow_sequence;

        statistics() {
            this->flow_export_counter = 0;
            this->flow_counter = 0;
            this->packet_counter = 0;
            this->flow_update_counter = 0;
            this->flow_sequence = 0;
        }

        void newFlow() {
            this->flow_counter++;
        }

        void newExport() {
            this->flow_export_counter++;
        }

        void newPacket() {
            this->packet_counter++;
        }

        void newFlowUpdate() {
            this->flow_update_counter++;
        }

        uint getFlows() {
            return this->flow_counter;
        }

        uint getPackets() {
            return this->packet_counter;
        }

        uint getExports() {
            return this->flow_export_counter;
        }

        uint getFlowUpdates() {
            return this->flow_update_counter;
        }

        void printStatistics() {
            std::cout << "\nTotal packets processed: " << std::to_string(this->packet_counter) << "\tFlows created: " << std::to_string(this->flow_counter);
            std::cout << "\tFlows exported: " << std::to_string(this->flow_export_counter) << "\tFlows updated: " << std::to_string(this->flow_update_counter) << "\n";
        }
};

class data {
    public:
        char* filePath = NULL;
        uint activeTimer;
        uint inactiveTimer;
        uint flowCacheSize;
        collector* clt;

        long SysUptime_diff;
        long SysUptime_end;
        long SysUptime_start;
        bool SysUptime_begin;
        timeval_s c_time;

        struct sniff_ip* ip;
        struct sniff_tcp* tcp;
        struct sniff_udp* udp;
        uint size_ip;

        char* src_ip;
        char* dst_ip;
        pcap_port src_port;
        pcap_port dst_port;
        protocol ip_protocol;
        tos ip_tos;

        bool tcp_header;
        const u_char* packet;
        uint8_t udp_data_send[NETFLOW_V5_DATASIZE] = { 0, };
        char* udp_address;
        char* udp_port;

        char errbuf[1024];

        struct bpf_program fp;		/* The compiled filter expression */
        char filter_exp[1024] = "icmp or tcp or udp";	/* The filter expression -> PROTOCOL (ICMP, TCP, UDP)*/
        
        bpf_u_int32 mask = 0;		/* The netmask of our sniffing device */
        bpf_u_int32 net = 0;		/* The IP of our sniffing device */
        int sock;

        bool udp_error = false;
        int udp_error_v = 0;
        char udp_error_str[1024];

        data() {
            this->filePath = NULL;
            this->activeTimer = 0;
            this->inactiveTimer = 0;
            this->flowCacheSize = 0;
            this->clt = new collector;

            this->SysUptime_diff = 0;
            this->SysUptime_begin = 0;
            this->SysUptime_end = 0;
            this->SysUptime_begin = false;

            this->size_ip = 0;
            
            this->src_ip = new char[1024];
            this->dst_ip = new char[1024];
        }
};

void loadUDPAddress(data* programData);

#endif