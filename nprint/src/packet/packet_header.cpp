/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "packet_header.hpp"

void PacketHeader::ascii_encode(unsigned char *ptr, uint32_t num_bytes,
                                std::vector<std::string> &to_fill) {
    uint32_t i;
    char *s, *t;

    s = new char[num_bytes * 2 + 1];

    t = s;
    for (i = 0; i < num_bytes; i++) {
        sprintf(t, "%c", (ptr[i]));
        t++;
    }
    to_fill.push_back(std::string(s));
    delete s;
}

/// @brief THIS IS THE FUNCTION THAT GETS THE BITS INSIDE EACH HEADER AND CONVERTS THEM TO A VECTOR 
/// OF 1'S,0'S AND -1'S 
/// @param num_bytes 
/// @param ptr 
/// @param to_fill 
/// @param fill_with 
void PacketHeader::make_bitstring(uint32_t num_bytes, void *ptr,
                                  std::vector<int8_t> &to_fill,
                                  int8_t fill_with) {
    uint8_t *byte, bit;
    uint32_t i;
    int32_t j;

    // create a string of -1's in the case the conctent is missing
    if (ptr == NULL) {
        for (i = 0; i < num_bytes * 8; i++)
            to_fill.push_back(fill_with);
        return;
    }

    // Copy the information pointed by ptr (usually the raw information in the headers (raw))
    // fill it into the final 
    byte = (uint8_t *)ptr;
    for (i = 0; i < num_bytes; i++) {
        for (j = 7; j >= 0; j--) {
            bit = (byte[i] >> j) & 1;
            to_fill.push_back(bit);
        }
    }
}

// This adds to the current bitstring the new bitstring
void PacketHeader::make_bitstring_header(
    const std::vector<std::tuple<std::string, uint32_t>> &v,
    std::vector<std::string> &to_fill) {
    uint32_t i;
    std::vector<std::tuple<std::string, uint32_t>>::const_iterator vit;
    for (vit = v.begin(); vit != v.end(); vit++) {
        for (i = 0; i < std::get<1>(*vit); i++) {
            to_fill.push_back(std::get<0>(*vit) + "_" + std::to_string(i));
        }
    }
}
