#include "isa_classes.hpp"
#include "isa_collector.hpp"
#include "isa.hpp"

bool argparse_collector(programArguments p, collector* clt) {
    bool isIP = true;
    if (p.isArgumentActive(p.id::NETFLOWCOLLECTOR)) {
        std::pair results = checkCollectorFormat(p.getArgumentParameter(p.id::NETFLOWCOLLECTOR));
        bool parseResult = std::get<0>(results);
        isIP = std::get<1>(results);

        if (!parseResult) {
            std::cout << "Wrong format of collector in parameter -c.";
            return false;
        }
    }

    std::pair host_port = clt->parseCollectorString(p.getArgumentParameter(p.id::NETFLOWCOLLECTOR));
    clt->setAddress(std::get<0>(host_port));

    if (std::get<1>(host_port).size() == 0)     // case: ip.address.here:<nothing>
        std::get<1>(host_port) = "2055";
    clt->setPort(std::get<1>(host_port));
    clt->setHostIP(isIP);

    return true;
}

bool argparse_isHelpActive(programArguments p) {
    if (p.isArgumentActive(p.id::HELP)) {
        std::cout << p.getArgumentParameter(p.id::HELP);
        return true;
    }
    return false;
}

bool argparse_checkNumericalValues(programArguments p, uint* activeTimer, uint* inactiveTimer, uint* flowCacheSize) {
    try {
        *activeTimer = stoi(p.getArgumentParameter(p.id::ACTIVETIMER));
    } catch (std::exception& e) {
        std::cerr << "Error while parsing active timer number at parameter -a. (" << e.what() << ")";
        return false;
    }

    try {
        *inactiveTimer = stoi(p.getArgumentParameter(p.id::INACTIVETIMER));
    } catch (std::exception& e) {
        std::cerr << "Error while parsing inactive timer number at parameter -i. (" << e.what() << ")" ;
        return false;
    }

    try {
        *flowCacheSize = stoi(p.getArgumentParameter(p.id::FLOWCACHE));
    } catch (std::exception& e) {
        std::cerr << "Error while parsing flow cache size at parameter -m. (" << e.what() << ")";
        return false;
    }

    // CHECK FOR INVALID VALUES
    if (*activeTimer == 0) {
        std::cerr << "Parameter -a requires positive number.\n";
        return false;
    }

    if (*inactiveTimer == 0) {
        std::cerr << "Parameter -i requires positive number.\n";
        return false;
    }
    return true;
}

void argparse_printReport(programArguments p, collector* clt, uint activeTimer, uint inactiveTimer, uint flowCacheSize) {
    std::cout << "---------------- ARGUMENTS  -----------\n";
    std::cout << "Active timer: " << std::to_string(activeTimer) << " seconds \n";
    std::cout << "Inactive timer: " << std::to_string(inactiveTimer) << " seconds\n";
    std::cout << "flowCache size: " << std::to_string(flowCacheSize) << " flows\n";
    std::cout << "File: " << (p.isArgumentActive(p.id::FILE) ? (p.getArgumentParameter(p.id::FILE)) : "stdin") << "\n";
    std::cout << "Collector host: " << clt->getAddress() << " / port: " << clt->getPort() << " / adressIsIP?: " << (clt->isHostIP() ? "yes" : "no") << "\n";
    std::cout << "---------------- BEGIN ---------------- \n\n";
}

void argparse_setFile(programArguments p, data* programData) {
    if (p.isArgumentActive(p.id::FILE)) {
        std::string f = p.getArgumentParameter(p.id::FILE);
        programData->filePath = new char[1024];
        const char* x = f.c_str();
        strcpy(programData->filePath, x);
    }
}