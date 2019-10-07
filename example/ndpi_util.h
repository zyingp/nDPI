/*
 * ndpi_util.h
 *
 * Copyright (C) 2011-18 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/**
 * This module contains routines to help setup a simple nDPI program.
 *
 * If you concern about performance or have to integrate nDPI in your
 * application, you could need to reimplement them yourself.
 *
 * WARNING: this API is just a demo od nDPI usage: Use it at your own risk!
 */
#ifndef __NDPI_UTIL_H__
#define __NDPI_UTIL_H__

#include <pcap.h>
#include "dsm.h"

#ifdef USE_DPDK
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE     128
#define TX_RING_SIZE     512
#define NUM_MBUFS       8191
#define MBUF_CACHE_SIZE  250
#define BURST_SIZE        32
#define PREFETCH_OFFSET    3

extern int dpdk_port_init(int port, struct rte_mempool *mbuf_pool);
#endif

#define MAX_NUM_READER_THREADS     16
#define IDLE_SCAN_PERIOD           10 /* msec (use TICK_RESOLUTION = 1000) */
#define MAX_IDLE_TIME           30000
#define MAX_FAST_PATH_IDLE_TIME  2000  /* msec for avoid stuck in fast-path*/
#define IDLE_SCAN_BUDGET         1024
#define NUM_ROOTS                 512
#define MAX_EXTRA_PACKETS_TO_CHECK  7
#define MAX_NDPI_FLOWS      200000000
#define TICK_RESOLUTION          1000
#define MAX_NUM_IP_ADDRESS          5  /* len of ip address array */
#define UPDATED_TREE                1
#define AGGRESSIVE_PERCENT      95.00
#define DIR_SRC                    10
#define DIR_DST                    20
#define PORT_ARRAY_SIZE            20
#define HOST_ARRAY_SIZE            20
#define FLOWS_PACKETS_THRESHOLD   0.9
#define FLOWS_PERCENT_THRESHOLD   1.0
#define FLOWS_PERCENT_THRESHOLD_2 0.2
#define FLOWS_THRESHOLD          1000
#define PKTS_PERCENT_THRESHOLD    0.1
#define MAX_TABLE_SIZE_1         4096
#define MAX_TABLE_SIZE_2         8192
#define INIT_VAL                   -1

// The max saved packet number for fast path
#define MAX_SAVED_PKT_NUM        11
//#define PRINT_FAST_PATH
// The max possible protocols for a rule
#define MAX_POSSIBLE_PROTOCOLS    5


#ifdef USE_FAST_PATH

typedef struct ndpi_savepkt_info
{
    uint8_t * saved_packets[MAX_SAVED_PKT_NUM];
    
    // is iph6 not iph? 1 for yes
    uint8_t    is_iph6[MAX_SAVED_PKT_NUM];
    // src is src but not dst, 1 for yes
    uint8_t src_is_src[MAX_SAVED_PKT_NUM];
    // offset to saved_packets, real iph/iph6 = saved_packets + iphoffset
    uint8_t  iphoffset[MAX_SAVED_PKT_NUM];
    
    u_int16_t                ipsize[MAX_SAVED_PKT_NUM];
    u_int64_t                  time[MAX_SAVED_PKT_NUM];
//    struct ndpi_id_struct      *src[MAX_SAVED_PKT_NUM], *dst[MAX_SAVED_PKT_NUM];
#ifdef PRINT_FAST_PATH
    // The original number of the saved packet, for debug only
    u_int64_t      packet_origin_no[MAX_SAVED_PKT_NUM];
#endif
    
}ndpi_savepkt_info_t;

#endif

// flow tracking
typedef struct ndpi_flow_info {
  u_int32_t hashval;
  u_int32_t src_ip;
  u_int32_t dst_ip;
  u_int16_t src_port;
  u_int16_t dst_port;
  u_int8_t detection_completed, protocol, bidirectional, check_extra_packets;
  u_int16_t vlan_id;
  struct ndpi_flow_struct *ndpi_flow;
  char src_name[48], dst_name[48];
  u_int8_t ip_version;
  u_int64_t last_seen;
  u_int64_t src2dst_bytes, dst2src_bytes;
  u_int32_t src2dst_packets, dst2src_packets;

#ifdef USE_FAST_PATH
    // Abort this flow and use old approach
    uint8_t   using_old_approach:1,
    // We have confirmed its protocols by using fast path, and reusing the protocols for following pkts
    using_found_fast_path:1,
    // Indicating whether we used the saved packet (1 for totally or partially used, 0 for never used)
    saved_pkt_used:1,
    // Indicating whether we determine the DSM rule to use (for matching thge matchexp)
    determing_rule:1,
    // Indicating that the flow is aborted for DPI since its protocol is not implemented yet
    is_aborted;
    
    // Save evaluation values for each flow
    struct dsm_flow_data flow_data;

    // The determined DSM rule's index in the rule array
    uint8_t rule_index;
    
    // The number of saved packets
    uint8_t  saved_pkt_num:4,
    used_pkt_num:4;          // the num of used packets in fast-path detection,
                             // and the unused ones should sent to process extra packet
    struct ndpi_savepkt_info *savepkt_info;
    
#endif
    
  // result only, not used for flow identification
  ndpi_protocol detected_protocol;

  char info[96];
  char host_server_name[256];
  char bittorent_hash[41];
  
  struct {
    char client_info[64], server_info[64], server_organization[64],
      ja3_client[33], ja3_server[33];
  } ssh_ssl;

  void *src_id, *dst_id;
} ndpi_flow_info_t;


// flow statistics info
typedef struct ndpi_stats {
  u_int32_t guessed_flow_protocols;
  u_int64_t raw_packet_count;
  u_int64_t ip_packet_count;
  u_int64_t total_wire_bytes, total_ip_bytes, total_discarded_bytes;
  u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t ndpi_flow_count;
  u_int64_t tcp_count, udp_count;
  u_int64_t mpls_count, pppoe_count, vlan_count, fragmented_count;
  u_int64_t packet_len[6];
  u_int16_t max_packet_len;
} ndpi_stats_t;


// flow preferences
typedef struct ndpi_workflow_prefs {
  u_int8_t decode_tunnels;
  u_int8_t quiet_mode;
  u_int32_t num_roots;
  u_int32_t max_ndpi_flows;
} ndpi_workflow_prefs_t;

struct ndpi_workflow;

/** workflow, flow, user data */
typedef void (*ndpi_workflow_callback_ptr) (struct ndpi_workflow *, struct ndpi_flow_info *, void *);


// workflow main structure
typedef struct ndpi_workflow {
  u_int64_t last_time;

  struct ndpi_workflow_prefs prefs;
  struct ndpi_stats stats;

  ndpi_workflow_callback_ptr __flow_detected_callback;
  void * __flow_detected_udata;
  ndpi_workflow_callback_ptr __flow_giveup_callback;
  void * __flow_giveup_udata;

  /* outside referencies */
  pcap_t *pcap_handle;

  /* allocated by prefs */
  void **ndpi_flows_root;
  struct ndpi_detection_module_struct *ndpi_struct;
  u_int32_t num_allocated_flows;
} ndpi_workflow_t;


/* TODO: remove wrappers parameters and use ndpi global, when their initialization will be fixed... */
struct ndpi_workflow * ndpi_workflow_init(const struct ndpi_workflow_prefs * prefs, pcap_t * pcap_handle);


 /* workflow main free function */
void ndpi_workflow_free(struct ndpi_workflow * workflow);


/** Free flow_info ndpi support structures but not the flow_info itself
 *
 *  TODO remove! Half freeing things is bad!
 */
void ndpi_free_flow_info_half(struct ndpi_flow_info *flow);


/* Process a packet and update the workflow  */
struct ndpi_proto ndpi_workflow_process_packet(struct ndpi_workflow * workflow,
					       const struct pcap_pkthdr *header,
					       const u_char *packet, uint8_t *donot_free_pkt);


/* flow callbacks for complete detected flow
   (ndpi_flow_info will be freed right after) */
static inline void ndpi_workflow_set_flow_detected_callback(struct ndpi_workflow * workflow, ndpi_workflow_callback_ptr callback, void * udata) {
  workflow->__flow_detected_callback = callback;
  workflow->__flow_detected_udata = udata;
}

/* flow callbacks for sufficient detected flow
   (ndpi_flow_info will be freed right after) */
static inline void ndpi_workflow_set_flow_giveup_callback(struct ndpi_workflow * workflow, ndpi_workflow_callback_ptr callback, void * udata) {
  workflow->__flow_giveup_callback = callback;
  workflow->__flow_giveup_udata = udata;
}


#ifdef USE_FAST_PATH

static inline void save_current_packet(struct ndpi_flow_info *flow,
                                       const u_int64_t time,
                                       const struct ndpi_iphdr *iph,
                                       struct ndpi_ipv6hdr *iph6,
                                       u_int16_t ipsize,
                                       struct ndpi_id_struct *src, struct ndpi_id_struct *dst,
                                       uint8_t *packet_checked, uint8_t *donot_free_pkt
#ifdef PRINT_FAST_PATH
                                       // The original number of the saved packet, for debug only
                                       ,u_int64_t      packet_origin_no
#endif
)
{
    
#ifdef PRINT_FAST_PATH
    printf("to save packet 0x%llx, original no:%llu\n", (uint64_t)(packet_checked), packet_origin_no);
#endif
    if (flow->saved_pkt_num >= MAX_SAVED_PKT_NUM) {
        printf("error: save too many packets, either enlarge buffer or do not save so many pkts.\n");
    }
    if (flow->savepkt_info == NULL) {
        flow->savepkt_info = malloc(sizeof(struct ndpi_savepkt_info));
        if (flow->savepkt_info != NULL) {
            memset(flow->savepkt_info, 0, sizeof(struct ndpi_savepkt_info));
        }else{
            printf("error: creating ndpi_savepkt_info\n");
            return;
        }
    }
    flow->savepkt_info->saved_packets[flow->saved_pkt_num] = packet_checked;
    if(iph != NULL)
    {
        flow->savepkt_info->iphoffset[flow->saved_pkt_num] = (char*)iph - (char*)packet_checked;
    }else{
        flow->savepkt_info->is_iph6[flow->saved_pkt_num] = 1;
        flow->savepkt_info->iphoffset[flow->saved_pkt_num] = (char*)iph6 - (char*)packet_checked;
    }
    flow->savepkt_info->ipsize[flow->saved_pkt_num] =ipsize;
    flow->savepkt_info->time[flow->saved_pkt_num] = time;
    flow->savepkt_info->src_is_src[flow->saved_pkt_num] = (src == flow->src_id)?1:0 ;
#ifdef PRINT_FAST_PATH
    // The original number of the saved packet, for debug only
    flow->savepkt_info->packet_origin_no[flow->saved_pkt_num] = packet_origin_no;
#endif
    
    (flow->saved_pkt_num) ++;
    *donot_free_pkt = (uint8_t)1;
    
}

static inline struct ndpi_flow_struct * create_ndpi_flow()
{
    struct ndpi_flow_struct * ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (ndpi_flow != NULL) {
        memset(ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
    }
    return ndpi_flow;
}

static inline uint8_t create_ndpi_flow_if_not(struct ndpi_flow_info *flow_info)
{
    if (flow_info->ndpi_flow == NULL) {
        flow_info->ndpi_flow = create_ndpi_flow();
        return 1;
    }
    return 0;
}

static inline void clean_saved_packets(struct ndpi_flow_info *flow_info)
{
    for (int i = 0; i< flow_info->saved_pkt_num; ++i) {
#ifdef PRINT_FAST_PATH
        //printf("to free saved packet 0x%llx, original no:%llu\n", (uint64_t)(flow_info->saved_packets[i]), flow_info->packet_origin_no[i]);
#endif
        free( flow_info->savepkt_info->saved_packets[i] );
        flow_info->savepkt_info->saved_packets[i] = NULL;
    }
    flow_info->saved_pkt_num = 0;
    free( flow_info->savepkt_info);
    flow_info->savepkt_info = NULL;
}

static inline ndpi_protocol apply_saved_pkt(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_info *flow_info)
{
    ndpi_protocol ret = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED };
    flow_info->saved_pkt_used = 1;
    flow_info->used_pkt_num = 0;
    for (int i = 0; i< flow_info->saved_pkt_num; ++i) {
#ifdef PRINT_FAST_PATH
        printf("applying saved index=%d packet, original no:%llu\n", i, flow_info->savepkt_info->packet_origin_no[i]);
#endif
        ret =
        ndpi_detection_process_packet(ndpi_struct, flow_info->ndpi_flow, flow_info->savepkt_info->saved_packets[i] + flow_info->savepkt_info->iphoffset[i],
                                      flow_info->savepkt_info->ipsize[i], flow_info->savepkt_info->time[i],
                                      (struct ndpi_id_struct *)((flow_info->savepkt_info->src_is_src[i] == 1)?flow_info->src_id:flow_info->dst_id),
                                      (struct ndpi_id_struct *)((flow_info->savepkt_info->src_is_src[i] == 1)?flow_info->dst_id:flow_info->src_id));
        ++(flow_info->used_pkt_num);
        if (ret.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
            break;
        }
    }
    return ret;
}

// Pre-declaration
void process_ndpi_collected_info(struct ndpi_workflow * workflow, struct ndpi_flow_info *flow) ;

static inline void apply_unused_saved_pkt_as_extra_packet(struct ndpi_workflow * workflow,
                                                          struct ndpi_flow_info *flow)
{
    // If there are some unused packet after using fast-path approach, we should feed them into extra packet processing
    /* Protocol already detected */
    if(flow->detection_completed && flow->used_pkt_num < flow->saved_pkt_num ) { //&& flow->using_old_approach == 1
        if(flow->check_extra_packets && flow->ndpi_flow != NULL && flow->ndpi_flow->check_extra_packets) {
            if(flow->ndpi_flow->num_extra_packets_checked == 0 && flow->ndpi_flow->max_extra_packets_to_check == 0) {
                /* Protocols can set this, but we set it here in case they didn't */
                flow->ndpi_flow->max_extra_packets_to_check = MAX_EXTRA_PACKETS_TO_CHECK;
            }
            for( int i = flow->used_pkt_num; i < flow->saved_pkt_num; ++i){
                if(flow->ndpi_flow->num_extra_packets_checked < flow->ndpi_flow->max_extra_packets_to_check) {
                    create_ndpi_flow_if_not(flow);
                    ndpi_process_extra_packet(workflow->ndpi_struct, flow->ndpi_flow, flow->savepkt_info->saved_packets[i] + flow->savepkt_info->iphoffset[i],
                     flow->savepkt_info->ipsize[i], flow->savepkt_info->time[i],
                     (struct ndpi_id_struct *)((flow->savepkt_info->src_is_src[i] == 1)?flow->src_id:flow->dst_id),
                     (struct ndpi_id_struct *)((flow->savepkt_info->src_is_src[i] == 1)?flow->dst_id:flow->src_id));
                    if (flow->ndpi_flow->check_extra_packets == 0) {
                        flow->check_extra_packets = 0;
                        process_ndpi_collected_info(workflow, flow);
                    }
                }
            }
            flow->used_pkt_num = flow->saved_pkt_num;  // mark all as used
            
        } else if (flow->ndpi_flow != NULL) {
            /* If this wasn't NULL we should do the half free */
            /* TODO: When half_free is deprecated, get rid of this */
            ndpi_free_flow_info_half(flow);
        }
    }
    
}

extern u_int8_t enable_protocol_guess;
static inline uint8_t check_saved_pkt_if_never_checked(struct ndpi_workflow * workflow, struct ndpi_flow_info *flow)
{
    uint8_t new_alloc = 0;
    if(flow->saved_pkt_num > 0 && flow->saved_pkt_used == 0)
    {
        // Do not count not enough packets case
        //extern uint64_t used_fast_path_flow_num_failed;
        //used_fast_path_flow_num_failed += 1;
        
        new_alloc = create_ndpi_flow_if_not(flow);
        flow->detected_protocol = apply_saved_pkt(workflow->ndpi_struct, flow);
        
        if((flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
           || ((flow->protocol == IPPROTO_UDP) && ((flow->src2dst_packets + flow->dst2src_packets) > 8))
           || ((flow->protocol == IPPROTO_TCP) && ((flow->src2dst_packets + flow->dst2src_packets) > 10))
           ) {
            /* New protocol detected or give up */
            flow->detection_completed = 1;
            /* Check if we should keep checking extra packets */
            if (flow->ndpi_flow->check_extra_packets)
                // ^since the ndpi_flow inside flow_info may be replaced, so always fetch
                flow->check_extra_packets = 1;
            
            if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
                flow->detected_protocol = ndpi_detection_giveup(workflow->ndpi_struct,
                                                                flow->ndpi_flow, enable_protocol_guess);
            process_ndpi_collected_info(workflow, flow);
        }
        
        // Free saved packets immediately
        clean_saved_packets(flow);
        
        // TODO: here should check apply extra packet if needed
    }
    return new_alloc;
}

#endif // USE_FAST_PATH



 /* compare two nodes in workflow */
int ndpi_workflow_node_cmp(const void *a, const void *b);
void process_ndpi_collected_info(struct ndpi_workflow * workflow, struct ndpi_flow_info *flow);
u_int32_t ethernet_crc32(const void* data, size_t n_bytes);
void ndpi_flow_info_freer(void *node);

extern int nDPI_LogLevel;

#endif
