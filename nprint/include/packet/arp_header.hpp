#ifndef ARP_H
#define ARP_H

#include <netinet/if_ether.h>

#include "packet_header.hpp"

class ArpHeader : public PacketHeader {
public:
    /* Required Functions */
    void *get_raw();
    void set_raw(void *other);
    void print_header(FILE *out);
    uint32_t get_header_len();
    void get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with);
    void get_bitstring_header(std::vector<std::string> &to_fill);

  private:
    struct ether_arp *raw = NULL;
};

#endif