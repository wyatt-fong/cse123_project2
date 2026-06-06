/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

static int sr_is_router_ip(struct sr_instance* sr, uint32_t ip);
static struct sr_if* sr_find_iface_by_mac(struct sr_instance* sr,
                                          const unsigned char* mac);
static struct sr_rt* sr_find_lpm_route(struct sr_instance* sr, uint32_t ip);
static int sr_valid_ip_packet(uint8_t* packet, unsigned int len);
static void sr_handle_arp(struct sr_instance* sr, uint8_t* packet,
                          unsigned int len, char* interface);
static void sr_handle_ip(struct sr_instance* sr, uint8_t* packet,
                         unsigned int len, char* interface);
static void sr_send_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* arp_hdr,
                              const char* interface);
static void sr_send_icmp_echo_reply(struct sr_instance* sr, uint8_t* packet,
                                    unsigned int len, char* interface);
static void sr_send_arp_request(struct sr_instance* sr, uint32_t ip,
                                const char* iface);
static void sr_forward_ip_packet(struct sr_instance* sr, uint8_t* packet,
                                 unsigned int len);
static void sr_send_routed_ip_packet(struct sr_instance* sr, uint8_t* packet,
                                     unsigned int len);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  if (len < sizeof(sr_ethernet_hdr_t)) {
    return;
  }

  if (ethertype(packet) == ethertype_arp) {
    sr_handle_arp(sr, packet, len, interface);
  } else if (ethertype(packet) == ethertype_ip) {
    sr_handle_ip(sr, packet, len, interface);
  }

}/* end sr_ForwardPacket */

static int sr_is_router_ip(struct sr_instance* sr, uint32_t ip)
{
  struct sr_if* iface = sr->if_list;

  while (iface) {
    if (iface->ip == ip) {
      return 1;
    }
    iface = iface->next;
  }

  return 0;
}

static struct sr_if* sr_find_iface_by_mac(struct sr_instance* sr,
                                          const unsigned char* mac)
{
  struct sr_if* iface = sr->if_list;

  while (iface) {
    if (memcmp(iface->addr, mac, ETHER_ADDR_LEN) == 0) {
      return iface;
    }
    iface = iface->next;
  }

  return NULL;
}

static struct sr_rt* sr_find_lpm_route(struct sr_instance* sr, uint32_t ip)
{
  struct sr_rt* rt = sr->routing_table;
  struct sr_rt* best = NULL;
  uint32_t best_mask = 0;

  while (rt) {
    uint32_t mask = ntohl(rt->mask.s_addr);

    if ((ip & rt->mask.s_addr) == (rt->dest.s_addr & rt->mask.s_addr) &&
        (!best || mask > best_mask)) {
      best = rt;
      best_mask = mask;
    }
    rt = rt->next;
  }

  return best;
}

static int sr_valid_ip_packet(uint8_t* packet, unsigned int len)
{
  sr_ip_hdr_t* ip_hdr;
  uint16_t received_sum;
  uint16_t computed_sum;
  unsigned int ip_header_len;

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    return 0;
  }

  ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  ip_header_len = ip_hdr->ip_hl * 4;

  if (ip_hdr->ip_v != 4 || ip_header_len < sizeof(sr_ip_hdr_t) ||
      len < sizeof(sr_ethernet_hdr_t) + ip_header_len ||
      ntohs(ip_hdr->ip_len) < ip_header_len ||
      len < sizeof(sr_ethernet_hdr_t) + ntohs(ip_hdr->ip_len)) {
    return 0;
  }

  received_sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  computed_sum = cksum(ip_hdr, ip_header_len);
  ip_hdr->ip_sum = received_sum;

  return received_sum == computed_sum;
}

static void sr_handle_arp(struct sr_instance* sr, uint8_t* packet,
                          unsigned int len, char* interface)
{
  sr_arp_hdr_t* arp_hdr;
  struct sr_arpreq* req;
  struct sr_packet* queued_pkt;

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    return;
  }

  arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  if (ntohs(arp_hdr->ar_op) == arp_op_request) {
    struct sr_if* recv_iface = sr_get_interface(sr, interface);
    if (recv_iface && arp_hdr->ar_tip == recv_iface->ip) {
      sr_send_arp_reply(sr, arp_hdr, interface);
    }
  } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
    if (!sr_is_router_ip(sr, arp_hdr->ar_tip)) {
      return;
    }

    req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
    if (req) {
      for (queued_pkt = req->packets; queued_pkt; queued_pkt = queued_pkt->next) {
        sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)queued_pkt->buf;
        struct sr_if* out_iface = sr_get_interface(sr, queued_pkt->iface);

        if (out_iface) {
          memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
          memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
          sr_send_packet(sr, queued_pkt->buf, queued_pkt->len, queued_pkt->iface);
        }
      }
      sr_arpreq_destroy(&(sr->cache), req);
    }
  }
}

static void sr_handle_ip(struct sr_instance* sr, uint8_t* packet,
                         unsigned int len, char* interface)
{
  sr_ip_hdr_t* ip_hdr;
  unsigned int ip_header_len;

  if (!sr_valid_ip_packet(packet, len)) {
    return;
  }

  ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  ip_header_len = ip_hdr->ip_hl * 4;

  if (sr_is_router_ip(sr, ip_hdr->ip_dst)) {
    if (ip_hdr->ip_p == ip_protocol_icmp &&
        ntohs(ip_hdr->ip_len) >= ip_header_len + sizeof(sr_icmp_t08_hdr_t)) {
      sr_icmp_t08_hdr_t* icmp_hdr =
        (sr_icmp_t08_hdr_t*)((uint8_t*)ip_hdr + ip_header_len);
      unsigned int icmp_len = ntohs(ip_hdr->ip_len) - ip_header_len;
      uint16_t received_sum = icmp_hdr->icmp_sum;

      icmp_hdr->icmp_sum = 0;
      if (icmp_hdr->icmp_type == 8 && received_sum == cksum(icmp_hdr, icmp_len)) {
        icmp_hdr->icmp_sum = received_sum;
        sr_send_icmp_echo_reply(sr, packet, len, interface);
      } else {
        icmp_hdr->icmp_sum = received_sum;
      }
    } else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
      sr_send_icmp_error(sr, packet, len, 3, 3);
    }
    return;
  }

  if (ip_hdr->ip_ttl <= 1) {
    sr_send_icmp_error(sr, packet, len, 11, 0);
    return;
  }

  ip_hdr->ip_ttl--;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_header_len);

  sr_forward_ip_packet(sr, packet, len);
}

static void sr_send_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* arp_hdr,
                              const char* interface)
{
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t* reply = (uint8_t*)malloc(len);
  sr_ethernet_hdr_t* eth_reply;
  sr_arp_hdr_t* arp_reply;
  struct sr_if* out_iface = sr_get_interface(sr, interface);

  if (!reply || !out_iface) {
    free(reply);
    return;
  }

  memset(reply, 0, len);
  eth_reply = (sr_ethernet_hdr_t*)reply;
  arp_reply = (sr_arp_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t));

  memcpy(eth_reply->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(eth_reply->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  eth_reply->ether_type = htons(ethertype_arp);

  arp_reply->ar_hrd = htons(arp_hrd_ethernet);
  arp_reply->ar_pro = htons(ethertype_ip);
  arp_reply->ar_hln = ETHER_ADDR_LEN;
  arp_reply->ar_pln = 4;
  arp_reply->ar_op = htons(arp_op_reply);
  memcpy(arp_reply->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  arp_reply->ar_sip = out_iface->ip;
  memcpy(arp_reply->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  arp_reply->ar_tip = arp_hdr->ar_sip;

  sr_send_packet(sr, reply, len, interface);
  free(reply);
}

static void sr_send_arp_request(struct sr_instance* sr, uint32_t ip,
                                const char* iface)
{
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t* request = (uint8_t*)malloc(len);
  sr_ethernet_hdr_t* eth_hdr;
  sr_arp_hdr_t* arp_hdr;
  struct sr_if* out_iface = sr_get_interface(sr, iface);
  unsigned char broadcast[ETHER_ADDR_LEN] =
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

  if (!request || !out_iface) {
    free(request);
    return;
  }

  memset(request, 0, len);
  eth_hdr = (sr_ethernet_hdr_t*)request;
  arp_hdr = (sr_arp_hdr_t*)(request + sizeof(sr_ethernet_hdr_t));

  memcpy(eth_hdr->ether_dhost, broadcast, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_arp);

  arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  arp_hdr->ar_pro = htons(ethertype_ip);
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = 4;
  arp_hdr->ar_op = htons(arp_op_request);
  memcpy(arp_hdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = out_iface->ip;
  memset(arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = ip;

  sr_send_packet(sr, request, len, iface);
  free(request);
}

static void sr_send_icmp_echo_reply(struct sr_instance* sr, uint8_t* packet,
                                    unsigned int len, char* interface)
{
  uint8_t* reply = (uint8_t*)malloc(len);
  sr_ethernet_hdr_t* eth_hdr;
  sr_ip_hdr_t* ip_hdr;
  sr_icmp_t08_hdr_t* icmp_hdr;
  unsigned int ip_header_len;
  unsigned int icmp_len;
  struct sr_if* out_iface = sr_get_interface(sr, interface);
  uint32_t old_src;

  if (!reply || !out_iface) {
    free(reply);
    return;
  }

  memcpy(reply, packet, len);
  eth_hdr = (sr_ethernet_hdr_t*)reply;
  ip_hdr = (sr_ip_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t));
  ip_header_len = ip_hdr->ip_hl * 4;
  icmp_hdr = (sr_icmp_t08_hdr_t*)((uint8_t*)ip_hdr + ip_header_len);
  icmp_len = ntohs(ip_hdr->ip_len) - ip_header_len;

  memcpy(eth_hdr->ether_dhost,
         ((sr_ethernet_hdr_t*)packet)->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);

  old_src = ip_hdr->ip_src;
  ip_hdr->ip_src = ip_hdr->ip_dst;
  ip_hdr->ip_dst = old_src;
  ip_hdr->ip_ttl = INIT_TTL;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_header_len);

  icmp_hdr->icmp_type = 0;
  icmp_hdr->icmp_code = 0;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_len);

  sr_send_packet(sr, reply, len, interface);
  free(reply);
}

void sr_send_icmp_error(struct sr_instance* sr, uint8_t* packet,
                        unsigned int len, uint8_t type, uint8_t code)
{
  sr_ip_hdr_t* old_ip_hdr;
  sr_ethernet_hdr_t* old_eth_hdr;
  struct sr_if* out_iface;
  unsigned int old_ip_len;
  unsigned int icmp_data_len;
  unsigned int reply_len;
  uint8_t* reply;
  sr_ethernet_hdr_t* eth_hdr;
  sr_ip_hdr_t* ip_hdr;
  sr_icmp_t11_hdr_t* icmp_hdr;

  if (!sr_valid_ip_packet(packet, len)) {
    return;
  }

  old_eth_hdr = (sr_ethernet_hdr_t*)packet;
  old_ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  old_ip_len = ntohs(old_ip_hdr->ip_len);
  out_iface = sr_find_iface_by_mac(sr, old_eth_hdr->ether_dhost);
  if (!out_iface) {
    struct sr_rt* route = sr_find_lpm_route(sr, old_ip_hdr->ip_src);

    if (!route) {
      return;
    }

    out_iface = sr_get_interface(sr, route->interface);
    if (!out_iface) {
      return;
    }
  }

  reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
              sizeof(sr_icmp_t11_hdr_t);
  reply = (uint8_t*)malloc(reply_len);
  if (!reply) {
    return;
  }

  memset(reply, 0, reply_len);
  eth_hdr = (sr_ethernet_hdr_t*)reply;
  ip_hdr = (sr_ip_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t));
  icmp_hdr = (sr_icmp_t11_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));

  memcpy(eth_hdr->ether_dhost, old_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_ip);

  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
  ip_hdr->ip_id = 0;
  ip_hdr->ip_off = 0;
  ip_hdr->ip_ttl = INIT_TTL;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_src = out_iface->ip;
  ip_hdr->ip_dst = old_ip_hdr->ip_src;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->unused = 0;
  icmp_data_len = old_ip_len < ICMP_DATA_SIZE ? old_ip_len : ICMP_DATA_SIZE;
  memcpy(icmp_hdr->data, old_ip_hdr, icmp_data_len);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t));

  sr_send_routed_ip_packet(sr, reply, reply_len);
  free(reply);
}

static void sr_forward_ip_packet(struct sr_instance* sr, uint8_t* packet,
                                 unsigned int len)
{
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  if (!sr_find_lpm_route(sr, ip_hdr->ip_dst)) {
    sr_send_icmp_error(sr, packet, len, 3, 0);
    return;
  }

  sr_send_routed_ip_packet(sr, packet, len);
}

static void sr_send_routed_ip_packet(struct sr_instance* sr, uint8_t* packet,
                                     unsigned int len)
{
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t* eth_hdr;
  struct sr_rt* route = sr_find_lpm_route(sr, ip_hdr->ip_dst);
  struct sr_if* out_iface;
  struct sr_arpentry* entry;
  struct sr_arpreq* req;
  uint32_t next_hop_ip;
  uint8_t* forwarded_packet;

  if (!route) {
    return;
  }

  out_iface = sr_get_interface(sr, route->interface);
  if (!out_iface) {
    return;
  }

  forwarded_packet = (uint8_t*)malloc(len);
  if (!forwarded_packet) {
    return;
  }

  memcpy(forwarded_packet, packet, len);
  eth_hdr = (sr_ethernet_hdr_t*)forwarded_packet;
  next_hop_ip = route->gw.s_addr ? route->gw.s_addr : ip_hdr->ip_dst;
  entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);

  if (entry) {
    memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
    sr_send_packet(sr, forwarded_packet, len, out_iface->name);
    free(entry);
    free(forwarded_packet);
    return;
  }

  req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip,
                             forwarded_packet, len, out_iface->name);

  if (req && req->times_sent == 0) {
    sr_send_arp_request(sr, req->ip, out_iface->name);
    req->sent = time(NULL);
    req->times_sent++;
  }

  free(forwarded_packet);
}
