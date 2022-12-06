#ifndef __ISA_FLOWEXPORT_HPP__
#define __ISA_FLOWEXPORT_HPP__

#include <map>
#include "isa_classes.hpp"

void exportActiveFlows(std::map<uint, struct Flow*>* flowCache, data* programData, statistics* stats);

void exportInactiveFlows(std::map<uint, struct Flow*>* flowCache, data* programData, statistics* stats);

void exportTCPFlows(std::map<uint, struct Flow*>* flowCache, data* programData, statistics* stats);

void exportRemainingFlows(std::map<uint, struct Flow*>* flowCache, data* programData, statistics* stats);

void exportOverflowFlows(std::map<uint, struct Flow*>* flowCache, data* programData, statistics* stats);

#endif