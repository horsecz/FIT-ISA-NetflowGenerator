#ifndef __ISA_BITSET_HPP__
#define __ISA_BITSET_HPP__
#include <bitset>

// Copying 8 Bytes of data into bitset array
void bitsetToBitset(std::bitset<NETFLOW_V5_DATASIZE>* dst, uint8_t bytes, uint* offset);

// Copying 16 Bytes of data into bitset array
void bitsetToBitset(std::bitset<NETFLOW_V5_DATASIZE>* dst, uint16_t bytes, uint* offset);

// Copying 32 Bytes of data into bitset array
void bitsetToBitset(std::bitset<NETFLOW_V5_DATASIZE>* dst, uint32_t bytes, uint* offset);

// Copy std::bitset array into char array 
void bitsetToChar(std::bitset<NETFLOW_V5_DATASIZE> src, uint8_t* dst);
#endif