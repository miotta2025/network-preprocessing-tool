#include "arp_header.hpp"


void *ArpHeader::get_raw(){
    return (void *) this->raw;
}

void ArpHeader::set_raw(void *other){
    this->raw = (struct ether_arp *)other;
}

void ArpHeader::print_header(FILE *out){
    //TODO
}

uint32_t ArpHeader::get_header_len(){
    return 28U;
}

void ArpHeader::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with){
    make_bitstring(this->get_header_len(), this->raw, to_fill, fill_with);
}

void ArpHeader::get_bitstring_header(std::vector<std::string> &to_fill){
    std::vector<std::tuple<std::string, uint32_t>> v;

    v.push_back(std::make_tuple("ar_hrd", 16));
    v.push_back(std::make_tuple("ar_pro", 16));
    v.push_back(std::make_tuple("ar_hln", 8));
    v.push_back(std::make_tuple("ar_pln", 8));
    v.push_back(std::make_tuple("ar_op", 16));
    v.push_back(std::make_tuple("arp_sha", 48));
    v.push_back(std::make_tuple("arp_spa", 32));
    v.push_back(std::make_tuple("arp_tha", 48));
    v.push_back(std::make_tuple("arp_tpa", 32));

    PacketHeader::make_bitstring_header(v, to_fill);
}
