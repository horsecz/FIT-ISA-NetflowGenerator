#include "isa.hpp"
#include "isa_collector.hpp"

/** parsing collector argument - checking IP format and determining type (hostname, IP) **/
std::pair<bool, bool> checkCollectorFormat(std::string c) {
    bool isIP = true;
    std::string host;
    std::string port;
    try {
        std::pair x = std::make_pair(c.substr(0, c.find(":")), c.substr(c.find(":")+1, c.size()));
        host = std::get<0>(x);
        port = std::get<1>(x);
        
        if (host != port) {
            if (port.size() != 0) {
                int port_int = stoi(port);
                if (port_int < 0) return std::make_pair(false, false);
            }
            
        }
    } catch (std::exception& e) {
        return std::make_pair(false, false);
    }
    
    try {
        std::string split = host.substr(0, host.find("."));
        stoi(split);

        host = host.substr(host.find(".")+1, host.size());
        split = host.substr(0, host.find("."));
        stoi(split);

        host = host.substr(host.find(".")+1, host.size());
        split = host.substr(0, host.find("."));
        stoi(split);

        host = host.substr(host.find(".")+1, host.size());
        split = host.substr(0, host.find("."));
        stoi(split);

    } catch (std::exception& e) {
        isIP = false;
    }

    return std::make_pair(true, isIP);
}

// code in this function borrowed and modified from: https://moodle.vut.cz/pluginfile.php/502893/mod_folder/content/0/udp/echo-udp-client2.c?forcedownload=1
int openUDPSocket(data* programData) {
    const char* address = programData->udp_address;
    const char* port = programData->udp_port;
    struct sockaddr_in server; // address structures of the server and the client
    struct hostent *servent;         // network host entry required by gethostbyname()         
    
    memset(&server,0,sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;                   

    // make DNS resolution of the first parameter using gethostbyname()
    if ((servent = gethostbyname(address)) == NULL) { // check the first parameter
        strcpy(programData->udp_error_str,"Translation of hostname to IP address failed!");
        programData->udp_error_v = ISA_RETURN_UDP_HOSTNAME;
        programData->udp_error = true;
        return ISA_RETURN_UDP_HOSTNAME;
    }

    // copy the first parameter to the server.sin_addr structure
    memcpy(&server.sin_addr,servent->h_addr,servent->h_length); 

    server.sin_port = htons(atoi(port));        // server port (network byte order)
    if ((programData->sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1) {   //create a client socket
        strcpy(programData->udp_error_str, "Creating new socket failed!");
        programData->udp_error_v = ISA_RETURN_UDP_SOCKET;
        programData->udp_error = true;
        return ISA_RETURN_UDP_SOCKET;
    }
    
    if (connect(programData->sock, (struct sockaddr *)&server, sizeof(server))  == -1) {
        strcpy(programData->udp_error_str, "Connecting to socket failed!");
        programData->udp_error_v = ISA_RETURN_UDP_CONNECT;
        programData->udp_error = true;
        return ISA_RETURN_UDP_CONNECT;
    }
    return ISA_RETURN_OK;
}

int exportToCollector(data* programData) {
    if (programData->udp_error)
        return programData->udp_error_v;

    int i = 0;
    i = send(programData->sock, programData->udp_data_send, NETFLOW_V5_DATASIZE, 0);
    
    if (i == -1) {   
        strcpy(programData->udp_error_str, "Exporting to collector was not successful!");
        programData->udp_error = true;
        return ISA_RETURN_UDP_SEND;
    } else if (i != NETFLOW_V5_DATASIZE) {
        strcpy(programData->udp_error_str, "Exporting to collector was successful only partially!");
        programData->udp_error = true;
        return ISA_RETURN_UDP_PARTIALSEND;
    }

    return ISA_RETURN_OK;
}

void closeUDPSocket(data* programData) {
    close(programData->sock);
}