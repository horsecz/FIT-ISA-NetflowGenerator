#include "isa.hpp"
#include "isa_bitset.hpp"

// Copying 8 Bytes of data into bitset array
void bitsetToBitset(std::bitset<NETFLOW_V5_DATASIZE>* dst, uint8_t bytes, uint* offset) {
    std::bitset<8> uint8_array(bytes);
    for (int i = 0; i < 8; i++) {
        dst->set(i+(*offset), uint8_array[i]);
    }
    (*offset) += 8;
}

// Copying 16 Bytes of data into bitset array
void bitsetToBitset(std::bitset<NETFLOW_V5_DATASIZE>* dst, uint16_t bytes, uint* offset) {
    std::bitset<16> uint16_array(bytes);
    for (int i = 0; i < 16; i++) {
        dst->set(i+(*offset), uint16_array[i]);
    }
    (*offset) += 16;
}

// Copying 32 Bytes of data into bitset array
void bitsetToBitset(std::bitset<NETFLOW_V5_DATASIZE>* dst, uint32_t bytes, uint* offset) {
    std::bitset<32> uint32_array(bytes);
    for (int i = 0; i < 32; i++) {
        dst->set(i+(*offset), uint32_array[i]);
    }
    (*offset) += 32;
}

void bitsetToChar(std::bitset<NETFLOW_V5_DATASIZE> src, uint8_t* dst) {
    const uint temp_size = 8;
    std::bitset<temp_size> temporary;
    unsigned long l = 0;
    uint8_t c = 0;

    for (uint j = 0; j < NETFLOW_V5_DATASIZE/temp_size; j++) {
        for (uint i = 0; i < temp_size; i++) {
            temporary.set(i, src[i+j*temp_size]);
        }
        l = temporary.to_ulong();
        c = static_cast<uint8_t> (l);
        dst[j] = c;
    }
}