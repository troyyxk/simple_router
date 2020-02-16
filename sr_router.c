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
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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

  /* fill in code here */
  struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)packet;

  /* handle ARP packet */
  if (e_hdr->ether_type == htons(ethertype_arp)) {
    int ARP_PACKET_LEN = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
    if (len < ARP_PACKET_LEN)
    { 
      return; 
    }

    /* ARP header */
    struct sr_arp_hdr* a_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
    struct sr_if* iface = 0;

    /* if ARP request */
    if (a_hdr->ar_op == htons(arp_op_request))
    {
      iface = sr_get_interface_by_ip(sr,a_hdr->ar_tip);
      if (iface)
      {
        uint8_t* reply_packet = malloc(ARP_PACKET_LEN);
        struct sr_ethernet_hdr* reply_ethernet_hdr = (struct sr_ethernet_hdr*)reply_packet;
        struct sr_arp_hdr* reply_arp_hdr = (struct sr_arp_hdr*)(reply_packet + sizeof(struct sr_ethernet_hdr));

        /* in reply's ethernet header, switch destination and source from the orginal packet*/
        reply_ethernet_hdr->ether_type = e_hdr->ether_type;
        memcpy(reply_ethernet_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN); 
        memcpy(reply_ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN); 

        /*set arp op type to reply*/
        reply_arp_hdr->ar_op = htons(arp_op_reply);
        reply_arp_hdr->ar_hln = a_hdr->ar_hln;
        reply_arp_hdr->ar_hrd = a_hdr->ar_hrd;
        reply_arp_hdr->ar_pln = a_hdr->ar_pln;
        reply_arp_hdr->ar_pro = a_hdr->ar_pro;
        /*change target address to the source of the original packet, and set source target as the interface we found*/
        reply_arp_hdr->ar_sip = iface->ip;
        memcpy(reply_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
        reply_arp_hdr->ar_tip = a_hdr->ar_sip;
        memcpy(reply_arp_hdr->ar_tha, a_hdr->ar_sha, ETHER_ADDR_LEN);



        sr_send_packet(sr, reply_packet, ARP_PACKET_LEN, iface->name);
        /*free(reply_packet);*/

        return;
        
      }
       
    } 
    /* if ARP reply */
    else if (a_hdr->ar_op == htons(arp_op_reply))
    {
      struct sr_arpcache *arp_cache = &(sr->cache);
      struct sr_arpreq* arp_request_entry = sr_arpcache_insert(arp_cache, a_hdr->ar_sha, a_hdr->ar_sip);

      if(arp_request_entry)
      {
        struct sr_packet* waiting_packet = arp_request_entry->packets;
        while (waiting_packet)
        {
          uint8_t *forward_packet = waiting_packet->buf;
          int forward_packet_len = waiting_packet->len;
          iface = sr_get_interface(sr, waiting_packet->iface);

          struct sr_ethernet_hdr* forward_ethernet_hdr = (struct sr_ethernet_hdr*)forward_packet;
          memcpy(forward_ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
          memcpy(forward_ethernet_hdr->ether_dhost, a_hdr->ar_sha, ETHER_ADDR_LEN);


          sr_send_packet(sr, forward_packet, forward_packet_len, iface->name);

          waiting_packet = waiting_packet->next;
        }
        
        sr_arpreq_destroy(arp_cache, arp_request_entry);
      }
    }
    
    
  }
  
  /* handle IP packet*/
  else
  {
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
    {
      return;
    }
    handle_ip_packet(sr, packet, len, interface);
    
  }
  

}/* end sr_ForwardPacket */


void handle_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));


  uint32_t target_ip = ip_hdr->ip_dst;


  /* Situations that target ip is one of router's interfaces*/
  struct sr_if* ip_match_router_iface = sr_get_interface_by_ip(sr, target_ip);
  if (ip_match_router_iface)
  {
    if (ip_hdr->ip_p == ip_protocol_icmp)
    {
      sr_icmp_hdr_t* icmp_hdr= (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0)
      {
        /* send echo reply */
        uint8_t* echo_reply = malloc(len);
        sr_ethernet_hdr_t* echo_reply_e_hdr = (sr_ethernet_hdr_t*)echo_reply;
        sr_ip_hdr_t* echo_reply_ip_hdr = (sr_ip_hdr_t*)(echo_reply + sizeof(sr_ethernet_hdr_t));
        sr_icmp_hdr_t* echo_reply_icmp_hdr = (sr_icmp_hdr_t*)(echo_reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        memcpy(echo_reply, packet, len);
        echo_reply_e_hdr->ether_type = htons(ethertype_ip);
        memcpy(echo_reply_e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(echo_reply_e_hdr->ether_shost, e_hdr->ether_dhost, ETHER_ADDR_LEN);

        
        
        echo_reply_ip_hdr->ip_ttl = 100;
      
        echo_reply_ip_hdr->ip_src = ip_hdr->ip_dst;
        echo_reply_ip_hdr->ip_dst = ip_hdr->ip_src;
        echo_reply_ip_hdr->ip_sum = 0;
        echo_reply_ip_hdr->ip_sum = cksum(echo_reply_ip_hdr, sizeof(sr_ip_hdr_t));

        
        echo_reply_icmp_hdr->icmp_type = 0;
        echo_reply_icmp_hdr->icmp_code = 0;
        echo_reply_icmp_hdr->icmp_sum = 0;
        echo_reply_icmp_hdr->icmp_sum = cksum(echo_reply_icmp_hdr, len - sizeof(sr_ethernet_hdr_t)- sizeof(sr_ip_hdr_t));

        send_ip_packet(sr, echo_reply, echo_reply_ip_hdr->ip_dst, len);

      }
      
    }
    else if(ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp)
    {
      send_icmp(sr, 3, 3, packet, len, ip_match_router_iface->name);
    }
    
    
    return;
  }


  /* Decrement TTL and check*/
  ip_hdr->ip_ttl --;
  if (ip_hdr->ip_ttl <= 0)
  {
    send_icmp(sr, 11, 0, packet, len, interface);
    return;
  }
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  if (!sr_get_lpm_entry(sr, target_ip))
  {
    send_icmp(sr, 3, 0, packet, len, interface);
    return;
  }

  
  
  /* Nothing wrong, finally forward packet*/
  send_ip_packet(sr, packet, target_ip, len);
}


struct sr_rt* sr_get_lpm_entry(struct sr_instance *sr, uint32_t ip) 
{
  struct sr_rt* rt_entry = sr->routing_table;
  uint32_t len_match = 0;
  struct sr_rt* best_match = NULL;

  while (rt_entry)
  {
    if ((ip & rt_entry->mask.s_addr) == (rt_entry->dest.s_addr & rt_entry->mask.s_addr))
    {
        if (len_match < (ip & rt_entry->dest.s_addr))
        {
            best_match = rt_entry;
            len_match = (ip & rt_entry->dest.s_addr);
        }
        
    }
    

    rt_entry = rt_entry->next;
  }

  return best_match;
  
}


void send_ip_packet(struct sr_instance *sr, uint8_t* packet, uint32_t target_ip, unsigned int len)
{
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*)packet;
  struct sr_rt* rt_entry = sr_get_lpm_entry(sr, target_ip);
  struct sr_if* fowarding_iface = sr_get_interface(sr, rt_entry->interface);


  struct sr_arpentry * entry = sr_arpcache_lookup(&(sr->cache), rt_entry->gw.s_addr);
  if (entry)
  {
    memcpy(e_hdr->ether_shost, fowarding_iface->addr, ETHER_ADDR_LEN);
    memcpy(e_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);

    sr_send_packet(sr, packet, len, fowarding_iface->name);
    free(entry);
    return;
  }
  else
  {
    struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), rt_entry->gw.s_addr, packet, len, fowarding_iface->name);
    handle_arpreq(sr, req);
  }

}

void send_icmp(struct sr_instance *sr, uint8_t type, uint8_t code, uint8_t* packet, unsigned int len, char* interface)
{
  /* Extract ip header from original packet in the entry*/
  struct sr_if* incoming_iface = sr_get_interface(sr, interface);
  struct sr_ip_hdr* packet_ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

  /* Get target mac and ip address from the header source*/
  uint32_t target_ip = packet_ip_hdr->ip_src;

  /* Create ICMP*/
  uint8_t* icmp = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  sr_ethernet_hdr_t* icmp_e_hdr = (sr_ethernet_hdr_t*)icmp;
  sr_ip_hdr_t* icmp_ip_hdr = (sr_ip_hdr_t*)(icmp + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*)(icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* ethernet header */
  icmp_e_hdr->ether_type = htons(ethertype_ip);
                

  /* ip header */
  icmp_ip_hdr->ip_v = packet_ip_hdr->ip_v;
  icmp_ip_hdr->ip_hl = packet_ip_hdr->ip_hl;
  icmp_ip_hdr->ip_tos = packet_ip_hdr ->ip_tos;
  icmp_ip_hdr->ip_len = htons(56);
  icmp_ip_hdr->ip_ttl = 100;
  icmp_ip_hdr->ip_off = htons(0x4000);
  icmp_ip_hdr->ip_p = ip_protocol_icmp;
  icmp_ip_hdr->ip_src = incoming_iface->ip;
  
  
  icmp_ip_hdr->ip_dst = target_ip;
  icmp_ip_hdr->ip_sum = 0;
  icmp_ip_hdr->ip_sum = cksum(icmp_ip_hdr, sizeof(sr_ip_hdr_t));

  /* icmp header */
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->next_mtu = 0;
  icmp_hdr->unused = 0;
  memcpy(icmp_hdr->data, packet_ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  send_ip_packet(sr, icmp, target_ip, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

}