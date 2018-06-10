/*
 * ndpi_util.h
 *
 * Copyright (C) 2011-16 - ntop.org
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
 * WARNING: this API is unstable! Use it at your own risk!
 */
#ifndef __NDPI_UTIL_H__
#define __NDPI_UTIL_H__

#include <pcap.h>

#define MAX_NUM_READER_THREADS     16
#define IDLE_SCAN_PERIOD           10 /* msec (use TICK_RESOLUTION = 1000) */
#define MAX_IDLE_TIME           30000
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
#define MAX_SAVED_PKT_NUM        20
//#define PRINT_FAST_PATH

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
    uint8_t   using_old_approach;
    // We have confirm its protocols by using fast path, and reusing the protocols for following pkts
    uint8_t   using_found_fast_path;
    // Indicating whether we used the saved packet (1 for totally or partially used, 0 for never used)
    uint8_t   saved_pkt_used;
    
    // Payload packet number
    u_int32_t src2dst_payload_pkt_num, dst2src_payload_pkt_num;
    u_int32_t tls_pkt_num;
    
    // TLS packet number
    u_int32_t src2dst_tls_pkt_num, dst2src_tls_pkt_num;
    
    uint8_t * saved_packets[MAX_SAVED_PKT_NUM];
    uint16_t  saved_pkt_num;
    uint16_t  used_pkt_num;  // the num of used packets in fast-path detection,
                             // and the unused ones should sent to process extra packet
    
    const struct ndpi_iphdr   *iph [MAX_SAVED_PKT_NUM];
    struct ndpi_ipv6hdr       *iph6[MAX_SAVED_PKT_NUM];
    u_int16_t                ipsize[MAX_SAVED_PKT_NUM];
    u_int64_t                  time[MAX_SAVED_PKT_NUM];
    struct ndpi_id_struct      *src[MAX_SAVED_PKT_NUM], *dst[MAX_SAVED_PKT_NUM];
#ifdef PRINT_FAST_PATH
    // The original number of the saved packet, for debug only
    u_int64_t      packet_origin_no[MAX_SAVED_PKT_NUM];
#endif
    
#endif

  // result only, not used for flow identification
  ndpi_protocol detected_protocol;

  char info[96];
  char host_server_name[256];
  char bittorent_hash[41];

  struct {
    char client_info[48], server_info[48];
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
					       const u_char *packet, uint8_t *packet_checked, uint8_t *donot_free_pkt);


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
    flow->saved_packets[flow->saved_pkt_num] = packet_checked;
    if(iph != NULL)
    {
        flow->iph[flow->saved_pkt_num] = iph;
    }else{
        flow->iph6[flow->saved_pkt_num] = iph6;
    }
    flow->ipsize[flow->saved_pkt_num] =ipsize;
    flow->time[flow->saved_pkt_num] = time;
    flow->src[flow->saved_pkt_num] = src;
    flow->dst[flow->saved_pkt_num] = dst;
#ifdef PRINT_FAST_PATH
    // The original number of the saved packet, for debug only
    flow->packet_origin_no[flow->saved_pkt_num] = packet_origin_no;
#endif
    
    flow->saved_pkt_num ++;
    *donot_free_pkt = (uint8_t)1;

}

// Return 1 if has payload and payload[index] == target
static inline uint8_t payload_is_equal(uint8_t *payload, u_int16_t payload_len, int index, uint8_t target)
{
    if (index >= payload_len) {
        return 0;
    }
    return (payload[index] == target)?1:0;
}

// Return 1 if has payload and payload[index_start index_start+length) == target[0,length)
static inline uint8_t payload_bytes_are_equal(uint8_t *payload, u_int16_t payload_len, int index_start,
                                       int length, uint8_t *target)
{
    if (index_start + length > payload_len) {
        return 0;
    }
    for (int i = 0 ; i < length ; ++i) {
        if (*(payload++) != *(target++)) {
            return 0;
        }
    }
    return 1;
}

static inline struct ndpi_flow_struct * create_ndpi_flow()
{
    struct ndpi_flow_struct * ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (ndpi_flow != NULL) {
        memset(ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
    }
    return ndpi_flow;
}

static inline void clean_saved_packets(struct ndpi_flow_info *flow_info)
{
    for (int i = 0; i< flow_info->saved_pkt_num; ++i) {
        free( flow_info->saved_packets[flow_info->saved_pkt_num] );
        flow_info->saved_packets[flow_info->saved_pkt_num] = NULL;
    }
    flow_info->saved_pkt_num = 0;
}

static inline ndpi_protocol apply_saved_pkt(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_info *flow_info)
{
    ndpi_protocol ret = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED };
    flow_info->saved_pkt_used = 1;
    flow_info->used_pkt_num = 0;
    for (int i = 0; i< flow_info->saved_pkt_num; ++i) {
#ifdef PRINT_FAST_PATH
        printf("applying saved index=%d packet, original no:%llu\n", i, flow_info->packet_origin_no[i]);
#endif
        ret =
           ndpi_detection_process_packet(ndpi_struct, flow_info->ndpi_flow,
                                      flow_info->iph[i] ? (uint8_t *)flow_info->iph[i] : (uint8_t *)flow_info->iph6[i],
                                      flow_info->ipsize[i], flow_info->time[i], flow_info->src[i], flow_info->dst[i]);
        ++(flow_info->used_pkt_num);
        if (ret.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
            break;
        }
    }
    return ret;
}

void process_ndpi_collected_info(struct ndpi_workflow * workflow, struct ndpi_flow_info *flow) ;

static inline void apply_unused_saved_pkt_as_extra_packet(struct ndpi_workflow * workflow,
                                                          struct ndpi_flow_info *flow)
{
    // If there are some unused packet after using fast-path approach, we should feed them into extra packet processing
    /* Protocol already detected */
    if(flow->detection_completed && flow->used_pkt_num < flow->saved_pkt_num && flow->using_old_approach == 1) {
        if(flow->check_extra_packets && flow->ndpi_flow != NULL && flow->ndpi_flow->check_extra_packets) {
            if(flow->ndpi_flow->num_extra_packets_checked == 0 && flow->ndpi_flow->max_extra_packets_to_check == 0) {
                /* Protocols can set this, but we set it here in case they didn't */
                flow->ndpi_flow->max_extra_packets_to_check = MAX_EXTRA_PACKETS_TO_CHECK;
            }
            for( int i = flow->used_pkt_num; i < flow->saved_pkt_num; ++i){
                if(flow->ndpi_flow->num_extra_packets_checked < flow->ndpi_flow->max_extra_packets_to_check) {
                    ndpi_detection_process_packet(workflow->ndpi_struct, flow->ndpi_flow,
                                                  flow->iph[i] ? (uint8_t *)flow->iph[i] : (uint8_t *)flow->iph6[i],
                                                  flow->ipsize[i], flow->time[i], flow->src[i], flow->dst[i]);
                    //                    ndpi_process_extra_packet(workflow->ndpi_struct, flow->ndpi_flow,
                    //                                              iph ? (uint8_t *)iph : (uint8_t *)iph6,
                    //                                              ipsize, time, src, dst);
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

static inline void check_saved_pkt_if_never_checked(struct ndpi_workflow * workflow, struct ndpi_flow_info *flow)
{
    if(flow->saved_pkt_num > 0 && flow->saved_pkt_used == 0)
    {
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
                                                                flow->ndpi_flow);
            process_ndpi_collected_info(workflow, flow);
        }
        
        // TODO: here should check apply extra packet if needed
    }
}

#endif // USE_FAST_PATH

 /* compare two nodes in workflow */
int ndpi_workflow_node_cmp(const void *a, const void *b);
void process_ndpi_collected_info(struct ndpi_workflow * workflow, struct ndpi_flow_info *flow);
u_int32_t ethernet_crc32(const void* data, size_t n_bytes);
void ndpi_flow_info_freer(void *node);

extern int nDPI_LogLevel;

#endif
