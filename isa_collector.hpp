#ifndef __ISA_COLLECTOR_HPP__
#define __ISA_COLLECTOR_HPP__

#include <err.h>
#include <utility>
#include <cstring>
#include <string>
#include "isa_classes.hpp"

// parsing collector argument - checking IP format and determining type (hostname, IP)
std::pair<bool, bool> checkCollectorFormat(std::string c);

int openUDPSocket(data* programData);

void closeUDPSocket(data* programData); 

// exports to collector (UDP)
int exportToCollector(data* programData);
#endif