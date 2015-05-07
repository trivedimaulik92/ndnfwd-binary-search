/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*-
 *  BSD LICENSE
 *  Copyright (c) 2014-2015, Washington University in St. Louis.
 *  All rights reserved.
 *
 *  Comments: Modified from the load balancer sample DPDK application provided in the
 *  original DPDK distribution to support binary search of hash tables for longest
 *  name prefix lookup using multiple cores.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <rte_hash_crc.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_lpm.h>

#include "main.h"
#include "ndn_header.h"
#include "hash_table.h"
#include "forwarding.h"
#include "rdtsc.h"
#include "siphash24.h"
#include "city.h"

#ifndef APP_LCORE_IO_FLUSH
#define APP_LCORE_IO_FLUSH           1000000
#endif

#ifndef APP_LCORE_WORKER_FLUSH
#define APP_LCORE_WORKER_FLUSH       1000000
#endif

#ifndef APP_STATS
#define APP_STATS                    1000000
#endif

#define APP_IO_RX_DROP_ALL_PACKETS   0
#define APP_WORKER_DROP_ALL_PACKETS  0
#define APP_IO_TX_DROP_ALL_PACKETS   0

#ifndef APP_IO_RX_PREFETCH_ENABLE
#define APP_IO_RX_PREFETCH_ENABLE    1
#endif

#ifndef APP_WORKER_PREFETCH_ENABLE
#define APP_WORKER_PREFETCH_ENABLE   1
#endif

#ifndef APP_IO_TX_PREFETCH_ENABLE
#define APP_IO_TX_PREFETCH_ENABLE    1
#endif

#if APP_IO_RX_PREFETCH_ENABLE
#define APP_IO_RX_PREFETCH0(p)       rte_prefetch0(p)
#define APP_IO_RX_PREFETCH1(p)       rte_prefetch1(p)
#else
#define APP_IO_RX_PREFETCH0(p)
#define APP_IO_RX_PREFETCH1(p)
#endif

#if APP_WORKER_PREFETCH_ENABLE
#define APP_WORKER_PREFETCH0(p)      rte_prefetch0(p)
#define APP_WORKER_PREFETCH1(p)      rte_prefetch1(p)
#else
#define APP_WORKER_PREFETCH0(p)
#define APP_WORKER_PREFETCH1(p)
#endif

#if APP_IO_TX_PREFETCH_ENABLE
#define APP_IO_TX_PREFETCH0(p)       rte_prefetch0(p)
#define APP_IO_TX_PREFETCH1(p)       rte_prefetch1(p)
#else
#define APP_IO_TX_PREFETCH0(p)
#define APP_IO_TX_PREFETCH1(p)
#endif

// Count the number of packets processed by each thread.
uint64_t total_count[APP_MAX_WORKER_LCORES];

#ifdef SIPHASH
#define FWD_KEYLEN 16
#endif

#define SIM_PROF // Measure the overall name prefix lookup throughput

// Binary Search with string verification
static inline uint32_t
basic_binary_search_verify_runtime(Hash_Table_t ** hts, int i, char * query, int * lens, uint64_t * hash_values) {
  int best_match = 0;
  int match_level = 0;
  int level = 0;
  char * addr = NULL;
  char * best_addr = NULL;
  uint64_t hash_value = 0;

  while(hts[i] != NULL) {
    // printf("i = %d, prefix = %.*s, hash_value = %" PRIu64 "\n", i, lens[i], query, hash_values[i]);

#if ENABLE_PREFETCH_NONE

#if G_HASH_CAL_PROF
  g_h_start = rdtsc();
#endif

#ifdef CITYHASH
  hash_value = CityHash64(query, lens[i]);
#endif

#ifdef SIPHASH
  hash_value = siphash((uint8_t *)query, lens[i], k);
#endif

#if G_HASH_CAL_PROF
  g_h_end = rdtsc();
  g_h_total += (g_h_end - g_h_start);
  g_h_total_count++;
#endif

#else
  hash_value = hash_values[i];
#endif

    // Requires string verification if there is a fingerprint match
    if (hash_table_lookup_verify(hts[i], query, lens[i], hash_value, &addr)) {
      best_match = i;
      match_level = level;
      best_addr = addr;
      i = hts[i]->right;
    } else {
      i = hts[i]->left;
    }

    level++;

    if (i == 0)
      break;
  }

  // match_result[best_match]++;

  return ((Fwd_Info_Entry_t *)(best_addr))->out_ports[match_level];
}

// String matching at the end of the search procedure.
static inline uint32_t
basic_binary_search_runtime(Hash_Table_t ** hts, int i, char * query, int * lens, uint64_t * hash_values) {
  int best_match = 0;
  int level = 0;
  int match_level = 0;
  char * addr = NULL;
  char * best_addr = NULL;
  uint64_t hash_value = 0;

  while(hts[i] != NULL) {
    // printf("i = %d, prefix = %.*s, hash_value = %" PRIu64 "\n", i, lens[i], query, hash_values[i]);

#if ENABLE_PREFETCH_NONE

#if G_HASH_CAL_PROF
 g_h_start = rdtsc();
#endif

#ifdef CITYHASH
  hash_value = CityHash64(query, lens[i]);
#endif

#ifdef SIPHASH
  hash_value = siphash((uint8_t *) query, lens[i], k);
#endif

#if G_HASH_CAL_PROF
  g_h_end = rdtsc();
  g_h_total += (g_h_end - g_h_start);
  g_h_total_count++;
#endif

#else
  hash_value = hash_values[i];
#endif

    if (hash_table_lookup(hts[i], query, lens[i], hash_value, &addr)) {
      best_match = i;
      match_level = level;
      best_addr = addr;
      i = hts[i]->right;
    } else {
      i = hts[i]->left;
    }

    level++;

    if (i == 0)
      break;
  }

#ifdef VERIFY_MATCHING
  if (memcmp(query, best_addr + FWD_INFO_SIZE, lens[best_match]) != 0) {
    return basic_binary_search_verify_runtime(hts, i, query, lens, hash_values);
  }
#endif

  uint32_t out_port = ((Fwd_Info_Entry_t *)(best_addr))->out_ports[match_level];
  // match_result[best_match]++;

  return out_port;
}

static inline void
app_lcore_io_rx_buffer_to_send (
  struct app_lcore_params_io *lp,
  uint32_t worker,
  struct rte_mbuf *mbuf,
  uint32_t bsz)
{
  uint32_t pos;
  int ret;

  pos = lp->rx.mbuf_out[worker].n_mbufs;
  lp->rx.mbuf_out[worker].array[pos ++] = mbuf;
  if (likely(pos < bsz)) {
    lp->rx.mbuf_out[worker].n_mbufs = pos;
    return;
  }

  ret = rte_ring_sp_enqueue_bulk(
    lp->rx.rings[worker],
    (void **) lp->rx.mbuf_out[worker].array,
    bsz);

  if (unlikely(ret == -ENOBUFS)) {
    uint32_t k;
    for (k = 0; k < bsz; k ++) {
      struct rte_mbuf *m = lp->rx.mbuf_out[worker].array[k];
      rte_pktmbuf_free(m);
    }
  }

  lp->rx.mbuf_out[worker].n_mbufs = 0;
  lp->rx.mbuf_out_flush[worker] = 0;

#if APP_STATS
  lp->rx.rings_iters[worker] ++;
  if (likely(ret == 0)) {
    lp->rx.rings_count[worker] ++;
  }
  if (unlikely(lp->rx.rings_iters[worker] == APP_STATS)) {
    unsigned lcore = rte_lcore_id();

    printf("\tI/O RX %u out (worker %u): enq success rate = %.2f\n",
      lcore,
      (unsigned)worker,
      ((double) lp->rx.rings_count[worker]) / ((double) lp->rx.rings_iters[worker]));
    lp->rx.rings_iters[worker] = 0;
    lp->rx.rings_count[worker] = 0;
  }
#endif
}

static inline void
app_lcore_io_rx(
  struct app_lcore_params_io *lp,
  uint32_t n_workers,
  uint32_t bsz_rd,
  uint32_t bsz_wr,
  uint8_t pos_lb)
{
#define ARRAY_SIZE 32

#ifdef SIM_PROF
  uint64_t s_start = 0, s_end = 0;
  static uint64_t s_diff[2] = {0,0};
  uint64_t s_count = 0;
#endif

  struct rte_mempool * mp = NULL;

  printf("io_thread rx_id = %d\n", lp->rx.rx_id);
  uint32_t start_worker = 0, end_worker = 0;

  if (lp->rx.rx_id == 0){ // If RX is on socket 0
    mp = lp->rx.pool_sim;
    start_worker = 1;
    end_worker = 7;
  } else {
    mp = lp->rx.pool_sim2;
    start_worker = 0;
    end_worker = 6;
  }

  Name_Entry_t * name_list = lp->rx.name_list;

  int line_count = lp->rx.line_count;
  int len = 0;
  int current = 0;
  int sim_empty_entries[APP_MAX_WORKER_LCORES];
  struct rte_mbuf * mbuf_array[APP_MAX_WORKER_LCORES][ARRAY_SIZE];

  uint32_t i = 0;
  int j = 0;
  for (i = 0; i < n_workers; i++) {
    sim_empty_entries[i] = ARRAY_SIZE;
    total_count[i] = 0;
  }

// start to profile
  char * dst = NULL;
  char * src = NULL;
  s_start = rdtsc();
  int run_count = 1;
  int run = 0;

  printf("Run experiments %d time(s).\n", run_count);

  while (run < run_count) {
    current = 0;
    while (current < (int)(line_count - n_workers * ARRAY_SIZE)) {

      for (i = 0; i < n_workers; i++) {
        for(j = 0; j < sim_empty_entries[i]; j++) {
          mbuf_array[i][j] = rte_pktmbuf_alloc(mp);
          dst = rte_pktmbuf_mtod(mbuf_array[i][j], char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr);
          src = name_list[current].name;
#ifdef NAME_OFFSET_1
          uint8_t name_length = ndn_hdr->name_length;
#endif

#ifdef NAME_OFFSET_2
          uint8_t name_length = (uint8_t)((src[1] - '0') * 10 + src[2] - '0');
#endif

#ifdef NAME_OFFSET_3
         uint8_t name_length = (uint8_t)((src[1] - '0') * 100 + (src[2] - '0') * 10 + src[3] - '0');
#endif

          len = (int)name_length;
          rte_memcpy(dst, name_list[current].name, len + NAME_OFFSET);
          s_count++;
          current++;
        }
        sim_empty_entries[i] -= j;
      }

      for (i = 0; i < n_workers; i++) {
        // if the queue allows ARRAY_SIZE buckets
        int free_count = rte_ring_free_count(lp->rx.rings[i]);
        if (free_count >= ARRAY_SIZE) {
          for (j = 0; j < (ARRAY_SIZE - sim_empty_entries[i]); j++) {
            app_lcore_io_rx_buffer_to_send(lp, i, mbuf_array[i][j], bsz_wr);
          }
          sim_empty_entries[i] = ARRAY_SIZE;
        }
      }
    }
    run++;
  }

  // Print results (MPPS)
  s_end = rdtsc();
  s_diff[lp->rx.rx_id] += s_end - s_start;
  double avg_latency = (double)s_diff[lp->rx.rx_id] / (double)s_count;

#ifdef SIPHASH
  printf("\t* SIPHASH\n");
#endif

#ifdef CITYHASH
  printf("\t* CITYHASH\n");
#endif

#ifdef ALWASY_MATCHING_VERIFY
  printf("\t* Always perform string verification\n");
#endif

#ifdef VERIFY_MATCHING
  printf("\t* String verification only at the end\n");
#endif

#if ENABLE_PREFETCH_ALL
  printf("\t** PREFETCH ALL\n");
#endif

#if ENABLE_PREFETCH_FIRST
  printf("\t** PREFETCH FIRST\n");
#endif

  uint64_t total_packets = 0;
  for(i = 0; i < n_workers; i++) {
    total_packets += total_count[i];
    printf("total_count[%d] = %" PRIu64 "\n", i, total_count[i]);
  }
  printf("total packets = %" PRIu64 "\n", total_packets);

#ifdef SIM_PROF
  printf("Total cycles = %" PRIu64 "\n", s_diff[lp->rx.rx_id]);
  printf("Total lookups = %" PRIu64 "\n", total_packets);
  avg_latency = (double)s_diff[lp->rx.rx_id] / (double)total_packets;
  printf("Ave lookup latency = %f cycles", avg_latency);
  printf("Avg throughput = %f MPPS\n", 2300.0 / avg_latency);
#endif

  printf("Exiting...\n");
  exit(0);
}


static inline void
app_lcore_io_rx_flush(struct app_lcore_params_io *lp, uint32_t n_workers)
{
  uint32_t worker;

  for (worker = 0; worker < n_workers; worker ++) {
    int ret;

    if (likely((lp->rx.mbuf_out_flush[worker] == 0) ||
               (lp->rx.mbuf_out[worker].n_mbufs == 0))) {
      lp->rx.mbuf_out_flush[worker] = 1;
      continue;
    }

    ret = rte_ring_sp_enqueue_bulk(
      lp->rx.rings[worker],
      (void **) lp->rx.mbuf_out[worker].array,
      lp->rx.mbuf_out[worker].n_mbufs);

    if (unlikely(ret < 0)) {
      uint32_t k;
      for (k = 0; k < lp->rx.mbuf_out[worker].n_mbufs; k ++) {
        struct rte_mbuf *pkt_to_free = lp->rx.mbuf_out[worker].array[k];
        rte_pktmbuf_free(pkt_to_free);
      }
    }

    lp->rx.mbuf_out[worker].n_mbufs = 0;
    lp->rx.mbuf_out_flush[worker] = 1;
  }
}

static inline void
app_lcore_io_tx(
  struct app_lcore_params_io *lp,
  uint32_t n_workers,
  uint32_t bsz_rd,
  uint32_t bsz_wr)
{
  uint32_t worker;

  for (worker = 0; worker < n_workers; worker ++) {
    uint32_t i;

    for (i = 0; i < lp->tx.n_nic_ports; i ++) {
      uint8_t port = lp->tx.nic_ports[i];
      struct rte_ring *ring = lp->tx.rings[port][worker];
      uint32_t n_mbufs, n_pkts;
      int ret;

      n_mbufs = lp->tx.mbuf_out[port].n_mbufs;
      ret = rte_ring_sc_dequeue_bulk(
        ring,
        (void **) &lp->tx.mbuf_out[port].array[n_mbufs],
        bsz_rd);

      if (unlikely(ret == -ENOENT)) {
        continue;
      }

      n_mbufs += bsz_rd;

#if APP_IO_TX_DROP_ALL_PACKETS
      {
        uint32_t j;
        APP_IO_TX_PREFETCH0(lp->tx.mbuf_out[port].array[0]);
        APP_IO_TX_PREFETCH0(lp->tx.mbuf_out[port].array[1]);

        static uint64_t total_count = 0;
        for (j = 0; j < n_mbufs; j ++) {
          if (likely(j < n_mbufs - 2)) {
            APP_IO_TX_PREFETCH0(lp->tx.mbuf_out[port].array[j + 2]);
          }

          rte_pktmbuf_free(lp->tx.mbuf_out[port].array[j]);
          total_count++;
          if (total_count % 1000000 == 0)
            printf("tx total_count = %" PRIu64 "\n", total_count);
        }

        lp->tx.mbuf_out[port].n_mbufs = 0;

        continue;
      }
#endif

      if (unlikely(n_mbufs < bsz_wr)) {
        lp->tx.mbuf_out[port].n_mbufs = n_mbufs;
        continue;
      }

      n_pkts = rte_eth_tx_burst(
        port,
        0,
        lp->tx.mbuf_out[port].array,
        (uint16_t) n_mbufs);

#if APP_STATS
      lp->tx.nic_ports_iters[port] ++;
      lp->tx.nic_ports_count[port] += n_pkts;
      if (unlikely(lp->tx.nic_ports_iters[port] == APP_STATS)) {
        unsigned lcore = rte_lcore_id();

        printf("\t\t\tI/O TX %u out (port %u): avg burst size = %.2f\n",
          lcore,
          (unsigned) port,
          ((double) lp->tx.nic_ports_count[port]) / ((double) lp->tx.nic_ports_iters[port]));
        lp->tx.nic_ports_iters[port] = 0;
        lp->tx.nic_ports_count[port] = 0;
      }
#endif

      if (unlikely(n_pkts < n_mbufs)) {
        uint32_t k;
        for (k = n_pkts; k < n_mbufs; k ++) {
          struct rte_mbuf *pkt_to_free = lp->tx.mbuf_out[port].array[k];
          rte_pktmbuf_free(pkt_to_free);
        }
      }
      lp->tx.mbuf_out[port].n_mbufs = 0;
      lp->tx.mbuf_out_flush[port] = 0;
    }
  }
}

static inline void
app_lcore_io_tx_flush(struct app_lcore_params_io *lp)
{
  uint8_t port;

  for (port = 0; port < lp->tx.n_nic_ports; port ++) {
    uint32_t n_pkts;

    if (likely((lp->tx.mbuf_out_flush[port] == 0) ||
               (lp->tx.mbuf_out[port].n_mbufs == 0))) {
      lp->tx.mbuf_out_flush[port] = 1;
      continue;
    }

    n_pkts = rte_eth_tx_burst(
      port,
      0,
      lp->tx.mbuf_out[port].array,
      (uint16_t) lp->tx.mbuf_out[port].n_mbufs);

    if (unlikely(n_pkts < lp->tx.mbuf_out[port].n_mbufs)) {
      uint32_t k;
      for (k = n_pkts; k < lp->tx.mbuf_out[port].n_mbufs; k ++) {
        struct rte_mbuf *pkt_to_free = lp->tx.mbuf_out[port].array[k];
        rte_pktmbuf_free(pkt_to_free);
      }
    }

    lp->tx.mbuf_out[port].n_mbufs = 0;
    lp->tx.mbuf_out_flush[port] = 1;
  }
}

static void
app_lcore_main_loop_io(void)
{
  uint32_t lcore = rte_lcore_id();
  struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;
  uint32_t n_workers = app_get_lcores_worker();
  uint64_t i = 0;

  uint32_t bsz_rx_rd = app.burst_size_io_rx_read;
  uint32_t bsz_rx_wr = app.burst_size_io_rx_write;
  uint32_t bsz_tx_rd = app.burst_size_io_tx_read;
  uint32_t bsz_tx_wr = app.burst_size_io_tx_write;

  uint8_t pos_lb = app.pos_lb;

  // for (; ; ) {
  //  app_lcore_io_rx(lp, n_workers, bsz_rx_rd, bsz_rx_wr, pos_lb);
  // }

  for ( ; ; ) {
    if (APP_LCORE_IO_FLUSH && (unlikely(i == APP_LCORE_IO_FLUSH))) {
      if (likely(lp->rx.n_nic_queues > 0)) {
        app_lcore_io_rx_flush(lp, n_workers);
      }

      if (likely(lp->tx.n_nic_ports > 0)) {
        app_lcore_io_tx_flush(lp);
      }

      i = 0;
    }

    // if (likely(lp->rx.n_nic_queues > 0)) {
      app_lcore_io_rx(lp, n_workers, bsz_rx_rd, bsz_rx_wr, pos_lb);
    // }

    // if (likely(lp->tx.n_nic_ports > 0)) {
      app_lcore_io_tx(lp, n_workers, bsz_tx_rd, bsz_tx_wr);
    // }

    i ++;
  }
}


static inline void
app_lcore_worker(
  struct app_lcore_params_worker *lp,
  uint32_t bsz_rd,
  uint32_t bsz_wr)
{
  uint32_t i;

  // For each RX queue
  for (i = 0; i < lp->n_rings_in; i++) {

    struct rte_ring *ring_in = lp->rings_in[i];
    uint32_t j = 0;
    int ret;

    ret = rte_ring_sc_dequeue_bulk(
      ring_in,
      (void **) lp->mbuf_in.array,
      bsz_rd);

    if (unlikely(ret == -ENOENT)) {
      continue;
    }

#if APP_WORKER_DROP_ALL_PACKETS
    for (j = 0; j < bsz_rd; j ++) {
      struct rte_mbuf *pkt = lp->mbuf_in.array[j];
      total_count[lp->worker_id]++;
      rte_pktmbuf_free(pkt);
    }

    continue;
#endif

  #ifdef SIPHASH
    const uint8_t k[FWD_KEYLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint64_t v0_s = 0x736f6d6570736575ULL;
    uint64_t v1_s = 0x646f72616e646f6dULL;
    uint64_t v2_s = 0x6c7967656e657261ULL;
    uint64_t v3_s = 0x7465646279746573ULL;
    uint64_t k0_s = U8TO64_LE( k );
    uint64_t k1_s = U8TO64_LE( k + 8 );
    v3_s ^= k1_s;
    v2_s ^= k0_s;
    v1_s ^= k1_s;
    v0_s ^= k0_s;
  #endif

    APP_WORKER_PREFETCH1(rte_pktmbuf_mtod(lp->mbuf_in.array[0], unsigned char *));
    APP_WORKER_PREFETCH0(lp->mbuf_in.array[1]);

    for (j = 0; j < bsz_rd; j ++) {
      struct rte_mbuf *pkt;
      struct ndn_hdr * ndn_hdr;
      uint32_t pos;
      uint8_t port = 0;

      if (likely(j < bsz_rd - 1)) {
        APP_WORKER_PREFETCH1(rte_pktmbuf_mtod(lp->mbuf_in.array[j+1], unsigned char *));
      }
      if (likely(j < bsz_rd - 2)) {
        APP_WORKER_PREFETCH0(lp->mbuf_in.array[j+2]);
      }

      pkt = lp->mbuf_in.array[j];
      ndn_hdr = (struct ndn_hdr *)(rte_pktmbuf_mtod(pkt, unsigned char *) +
                sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
#ifdef NAME_OFFSET_1
       uint8_t name_length = ndn_hdr->name_length;
#endif

#ifdef NAME_OFFSET_2
       uint8_t name_length = (uint8_t)((ndn_hdr->name_length[0] - '0') * 10 + ndn_hdr->name_length[1] - '0');
#endif

#ifdef NAME_OFFSET_3
       uint8_t name_length = (uint8_t)((ndn_hdr->name_length[0] - '0') * 100 + (ndn_hdr->name_length[1] - '0') * 10 + ndn_hdr->name_length[2] - '0');
#endif

      if (name_length > 0) {
        Hash_Table_t ** hts = (struct Hash_Table **)(lp->hts);

#ifdef HASH_CAL_PROF_RUNTIME
        static uint64_t hash_count = 0;
        uint64_t h_start, h_end, hdiff;
#endif

#ifdef SIPHASH
        uint64_t v0 = v0_s;
        uint64_t v1 = v1_s;
        uint64_t v2 = v2_s;
        uint64_t v3 = v3_s;
#endif

        int max_comp = 1;
        int len = 0;
        int lens[MAX_COMP_NUM];
        char * prefix = (char*)((char *)ndn_hdr + NAME_OFFSET);

#ifdef SIPHASH
        uint8_t * in = (uint8_t *)prefix;
#endif

/*
      int cur = 0;
      while(prefix[cur] != '\0' && prefix[cur] != '\n') {
        len++;
        if (prefix[cur] == '/') {
          lens[max_comp] = len;
          max_comp++;
        }
        cur++;
        if (max_comp >= MAX_COMP_NUM)
          break;
      }

*/

// /*
        char * pch;
        pch=strchr(prefix,'/');
        while (pch!=NULL) {
          lens[max_comp] = pch-prefix+1;
          assert(lens[max_comp] > 0);
          max_comp++;
          pch=strchr(pch+1,'/');
          if (max_comp >= MAX_COMP_NUM)
          break;
        }
//  */
        if (max_comp > MAX_COMP_NUM) max_comp = MAX_COMP_NUM;

        uint64_t hash_values[MAX_COMP_NUM];
        int comp = 1;
        for (comp = 1; comp < max_comp; comp++) {
          len = lens[comp];

#ifdef CRCHASH
        hash_values[comp] = crc_hash_runtime(prefix, len);
#endif

#ifdef CITYHASH
        hash_values[comp] = CityHash64(prefix, len);
#endif

#ifdef SIPHASH
      const uint8_t *end = (uint8_t *)prefix + len - ( len % 8);
      siphash_step(&v0, &v1, &v2, &v3, &in, end, len, &hash_values[comp]);
#endif

      // printf("comp = %d, len = %d, hash_value = %" PRIu64 "\n", comp, len, hash_values[comp]);

#if ENABLE_PREFETCH_ALL
          uint32_t loc = (hash_values[comp] >> 32) % hts[comp]->size;
          uint32_t offset = loc & 0xffffff;
          uint32_t block_index = loc >> 24;
          prefetch((void *) &(hts[comp]->buckets[block_index][offset]));
#endif

#if ENABLE_PREFETCH_FIRST
          if (comp == FIRST_HT){
            uint32_t loc = (hash_values[comp] >> 32) % hts[comp]->size;
            uint32_t offset = loc & 0xffffff;
            uint32_t block_index = loc >> 24;
            prefetch((void *) &(hts[comp]->buckets[block_index][offset]));
    }
#endif

        } // for (comp = 1 ...)

        // Perform longest prefix lookup via hash table
#ifdef ALWASY_MATCHING_VERIFY
        port = basic_binary_search_verify_runtime(hts, FIRST_HT, prefix, lens, hash_values);
#else
        port = basic_binary_search_runtime(hts, FIRST_HT, prefix, lens, hash_values);
#endif
      } // if (name_length > 0)

      // printf("Port = %u\n", (uint32_t)(port));
      assert(port == 1);
      // Update Dst MAC address

      total_count[lp->worker_id]++;

// Currently, free all the packets at the worker
#if 0
    rte_pktmbuf_free(pkt);
    continue;
#endif

      pos = lp->mbuf_out[port].n_mbufs;

      lp->mbuf_out[port].array[pos ++] = pkt;
      if (likely(pos < bsz_wr)) {
        lp->mbuf_out[port].n_mbufs = pos;
        continue;
      }

      ret = rte_ring_sp_enqueue_bulk(
        lp->rings_out[port],
        (void **) lp->mbuf_out[port].array,
        bsz_wr);

#if APP_STATS
      lp->rings_out_iters[port] ++;
      if (ret == 0) {
        lp->rings_out_count[port] += 1;
      }
      if (lp->rings_out_iters[port] == APP_STATS){
        printf("\t\tWorker %u out (NIC port %u): enq success rate = %.2f\n",
          (unsigned) lp->worker_id,
          (unsigned) port,
          ((double) lp->rings_out_count[port]) / ((double) lp->rings_out_iters[port]));
        lp->rings_out_iters[port] = 0;
        lp->rings_out_count[port] = 0;
      }

#endif

      if (unlikely(ret == -ENOBUFS)) {
        uint32_t k;
        for (k = 0; k < bsz_wr; k ++) {
          struct rte_mbuf *pkt_to_free = lp->mbuf_out[port].array[k];
          rte_pktmbuf_free(pkt_to_free);
        }
      }

      lp->mbuf_out[port].n_mbufs = 0;
      lp->mbuf_out_flush[port] = 0;
    }
  }
}

static inline void
app_lcore_worker_flush(struct app_lcore_params_worker *lp)
{
  uint32_t port;

  for (port = 0; port < APP_MAX_NIC_PORTS; port ++) {
    int ret;

    if (unlikely(lp->rings_out[port] == NULL)) {
      continue;
    }

    if (likely((lp->mbuf_out_flush[port] == 0) ||
               (lp->mbuf_out[port].n_mbufs == 0))) {
      lp->mbuf_out_flush[port] = 1;
      continue;
    }

    ret = rte_ring_sp_enqueue_bulk(
      lp->rings_out[port],
      (void **) lp->mbuf_out[port].array,
      lp->mbuf_out[port].n_mbufs);

    if (unlikely(ret < 0)) {
      uint32_t k;
      for (k = 0; k < lp->mbuf_out[port].n_mbufs; k ++) {
        struct rte_mbuf *pkt_to_free = lp->mbuf_out[port].array[k];
        rte_pktmbuf_free(pkt_to_free);
      }
    }

    lp->mbuf_out[port].n_mbufs = 0;
    lp->mbuf_out_flush[port] = 1;
  }
}

static void
app_lcore_main_loop_worker(void) {

  uint32_t lcore = rte_lcore_id();
  struct app_lcore_params_worker *lp = &app.lcore_params[lcore].worker;
  uint64_t i = 0;

  uint32_t bsz_rd = app.burst_size_worker_read;
  uint32_t bsz_wr = app.burst_size_worker_write;

  for ( ; ; ) {
    if (APP_LCORE_WORKER_FLUSH && (unlikely(i == APP_LCORE_WORKER_FLUSH))) {
      app_lcore_worker_flush(lp);
      i = 0;
    }

    app_lcore_worker(lp, bsz_rd, bsz_wr);

    i ++;
  }
}

int
app_lcore_main_loop(__attribute__((unused)) void *arg)
{
  struct app_lcore_params *lp;
  unsigned lcore;

  lcore = rte_lcore_id();
  lp = &app.lcore_params[lcore];

  if (lp->type == e_APP_LCORE_IO) {
    printf("Logical core %u (I/O) main loop.\n", lcore);
    app_lcore_main_loop_io();
  }

  if (lp->type == e_APP_LCORE_WORKER) {
    printf("Logical core %u (worker %u) main loop.\n",
      lcore,
      (unsigned) lp->worker.worker_id);
    app_lcore_main_loop_worker();
  }

  return 0;
}
