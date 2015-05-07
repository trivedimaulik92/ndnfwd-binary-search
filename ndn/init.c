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
 *  name prefix lookup with real network traffic.
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
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_lpm.h>
#include <rte_malloc.h>

#include "main.h"
#include "hash_table.h"
#include "forwarding.h"
#include "fwd_info.h"

#include "siphash24.h"
#include "city.h"

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode	= ETH_MQ_RX_RSS,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 1, /**< IP checksum offload enabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = APP_DEFAULT_NIC_RX_PTHRESH,
		.hthresh = APP_DEFAULT_NIC_RX_HTHRESH,
		.wthresh = APP_DEFAULT_NIC_RX_WTHRESH,
	},
	.rx_free_thresh = APP_DEFAULT_NIC_RX_FREE_THRESH,
	.rx_drop_en = APP_DEFAULT_NIC_RX_DROP_EN,
};

static struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = APP_DEFAULT_NIC_TX_PTHRESH,
		.hthresh = APP_DEFAULT_NIC_TX_HTHRESH,
		.wthresh = APP_DEFAULT_NIC_TX_WTHRESH,
	},
	.tx_free_thresh = APP_DEFAULT_NIC_TX_FREE_THRESH,
	.tx_rs_thresh = APP_DEFAULT_NIC_TX_RS_THRESH,
};

static void
app_assign_worker_ids(void)
{
	uint32_t lcore, worker_id;

	/* Assign ID for each worker */
	worker_id = 0;
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore].worker;

		if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER) {
			continue;
		}

		lp_worker->worker_id = worker_id;
		worker_id ++;
	}
}

static void
app_init_mbuf_pools(void)
{
	unsigned socket, lcore;

	/* Init the buffer pools */
	for (socket = 0; socket < APP_MAX_SOCKETS; socket ++) {
		char name[32];
		if (app_is_socket_used(socket) == 0) {
			continue;
		}

		snprintf(name, sizeof(name), "mbuf_pool_%u", socket);
		printf("Creating the mbuf pool for socket %u ...\n", socket);
		app.pools[socket] = rte_mempool_create(
			name,
			APP_DEFAULT_MEMPOOL_BUFFERS,
			APP_DEFAULT_MBUF_SIZE,
			APP_DEFAULT_MEMPOOL_CACHE_SIZE,
			sizeof(struct rte_pktmbuf_pool_private),
			rte_pktmbuf_pool_init, NULL,
			rte_pktmbuf_init, NULL,
			socket,
			0);
		if (app.pools[socket] == NULL) {
			rte_panic("Cannot create mbuf pool on socket %u\n", socket);
		}
	}

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		if (app.lcore_params[lcore].type == e_APP_LCORE_DISABLED) {
			continue;
		}

		socket = rte_lcore_to_socket_id(lcore);
		app.lcore_params[lcore].pool = app.pools[socket];
	}
}

static void
app_init_lpm_tables(void)
{
	unsigned socket, lcore;

	/* Init the LPM tables */
	for (socket = 0; socket < APP_MAX_SOCKETS; socket ++) {
		char name[32];
		uint32_t rule;

		if (app_is_socket_used(socket) == 0) {
			continue;
		}

		snprintf(name, sizeof(name), "lpm_table_%u", socket);
		printf("Creating the LPM table for socket %u ...\n", socket);
		app.lpm_tables[socket] = rte_lpm_create(
			name,
			socket,
			APP_MAX_LPM_RULES,
			0);
		if (app.lpm_tables[socket] == NULL) {
			rte_panic("Unable to create LPM table on socket %u\n", socket);
		}

		for (rule = 0; rule < app.n_lpm_rules; rule ++) {
			int ret;

			ret = rte_lpm_add(app.lpm_tables[socket],
				app.lpm_rules[rule].ip,
				app.lpm_rules[rule].depth,
				app.lpm_rules[rule].if_out);

			if (ret < 0) {
				rte_panic("Unable to add entry %u (%x/%u => %u) to the LPM table on socket %u (%d)\n",
					(unsigned) rule,
					(unsigned) app.lpm_rules[rule].ip,
					(unsigned) app.lpm_rules[rule].depth,
					(unsigned) app.lpm_rules[rule].if_out,
					socket,
					ret);
			}
		}

	}

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER) {
			continue;
		}

		socket = rte_lcore_to_socket_id(lcore);
		app.lcore_params[lcore].worker.lpm_table = app.lpm_tables[socket];
	}
}

static void
app_init_rings_rx(void)
{
	unsigned lcore;

	/* Initialize the rings for the RX side */
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;
		unsigned socket_io, lcore_worker;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
		    (lp_io->rx.n_nic_queues == 0)) {
			continue;
		}

		socket_io = rte_lcore_to_socket_id(lcore);

		for (lcore_worker = 0; lcore_worker < APP_MAX_LCORES; lcore_worker ++) {
			char name[32];
			struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore_worker].worker;
			struct rte_ring *ring = NULL;

			if (app.lcore_params[lcore_worker].type != e_APP_LCORE_WORKER) {
				continue;
			}

			printf("Creating ring to connect I/O lcore %u (socket %u) with worker lcore %u ...\n",
				lcore,
				socket_io,
				lcore_worker);
			snprintf(name, sizeof(name), "app_ring_rx_s%u_io%u_w%u",
				socket_io,
				lcore,
				lcore_worker);
			ring = rte_ring_create(
				name,
				app.ring_rx_size,
				socket_io,
				RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (ring == NULL) {
				rte_panic("Cannot create ring to connect I/O core %u with worker core %u\n",
					lcore,
					lcore_worker);
			}

			lp_io->rx.rings[lp_io->rx.n_rings] = ring;
			lp_io->rx.n_rings ++;

			lp_worker->rings_in[lp_worker->n_rings_in] = ring;
			lp_worker->n_rings_in ++;
		}
	}

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
		    (lp_io->rx.n_nic_queues == 0)) {
			continue;
		}

		if (lp_io->rx.n_rings != app_get_lcores_worker()) {
			rte_panic("Algorithmic error (I/O RX rings)\n");
		}
	}

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore].worker;

		if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER) {
			continue;
		}

		if (lp_worker->n_rings_in != app_get_lcores_io_rx()) {
			rte_panic("Algorithmic error (worker input rings)\n");
		}
	}
}

static void
app_init_rings_tx(void)
{
	unsigned lcore;

	/* Initialize the rings for the TX side */
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore].worker;
		unsigned port;

		if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER) {
			continue;
		}

		for (port = 0; port < APP_MAX_NIC_PORTS; port ++) {
			char name[32];
			struct app_lcore_params_io *lp_io = NULL;
			struct rte_ring *ring;
			uint32_t socket_io, lcore_io;

			if (app.nic_tx_port_mask[port] == 0) {
				continue;
			}

			if (app_get_lcore_for_nic_tx((uint8_t) port, &lcore_io) < 0) {
				rte_panic("Algorithmic error (no I/O core to handle TX of port %u)\n",
					port);
			}

			lp_io = &app.lcore_params[lcore_io].io;
			socket_io = rte_lcore_to_socket_id(lcore_io);

			printf("Creating ring to connect worker lcore %u with TX port %u (through I/O lcore %u) (socket %u) ...\n",
				lcore, port, (unsigned)lcore_io, (unsigned)socket_io);
			snprintf(name, sizeof(name), "app_ring_tx_s%u_w%u_p%u", socket_io, lcore, port);
			ring = rte_ring_create(
				name,
				app.ring_tx_size,
				socket_io,
				RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (ring == NULL) {
				rte_panic("Cannot create ring to connect worker core %u with TX port %u\n",
					lcore,
					port);
			}

			lp_worker->rings_out[port] = ring;
			lp_io->tx.rings[port][lp_worker->worker_id] = ring;
		}
	}

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
		struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;
		unsigned i;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
		    (lp_io->tx.n_nic_ports == 0)) {
			continue;
		}

		for (i = 0; i < lp_io->tx.n_nic_ports; i ++){
			unsigned port, j;

			port = lp_io->tx.nic_ports[i];
			for (j = 0; j < app_get_lcores_worker(); j ++) {
				if (lp_io->tx.rings[port][j] == NULL) {
					rte_panic("Algorithmic error (I/O TX rings)\n");
				}
			}
		}
	}
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	uint32_t n_rx_queues, n_tx_queues;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			n_rx_queues = app_get_nic_rx_queues_per_port(portid);
			n_tx_queues = app.nic_tx_port_mask[portid];
			if ((n_rx_queues == 0) && (n_tx_queues == 0))
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
							(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void
app_init_nics(void)
{
	unsigned socket;
	uint32_t lcore;
	uint8_t port, queue;
	int ret;
	uint32_t n_rx_queues, n_tx_queues;

	if (rte_eal_pci_probe() < 0) {
		rte_panic("Cannot probe PCI\n");
	}

	/* Init NIC ports and queues, then start the ports */
	for (port = 0; port < APP_MAX_NIC_PORTS; port ++) {
		struct rte_mempool *pool;

		n_rx_queues = app_get_nic_rx_queues_per_port(port);
		n_tx_queues = app.nic_tx_port_mask[port];

		if ((n_rx_queues == 0) && (n_tx_queues == 0)) {
			continue;
		}

		/* Init port */
		printf("Initializing NIC port %u ...\n", (unsigned) port);
		ret = rte_eth_dev_configure(
			port,
			(uint8_t) n_rx_queues,
			(uint8_t) n_tx_queues,
			&port_conf);
		if (ret < 0) {
			rte_panic("Cannot init NIC port %u (%d)\n", (unsigned) port, ret);
		}
		rte_eth_promiscuous_enable(port);

		/* Init RX queues */
		for (queue = 0; queue < APP_MAX_RX_QUEUES_PER_NIC_PORT; queue ++) {
			if (app.nic_rx_queue_mask[port][queue] == 0) {
				continue;
			}

			app_get_lcore_for_nic_rx(port, queue, &lcore);
			socket = rte_lcore_to_socket_id(lcore);
			pool = app.lcore_params[lcore].pool;

			printf("Initializing NIC port %u RX queue %u ...\n",
				(unsigned) port,
				(unsigned) queue);
			ret = rte_eth_rx_queue_setup(
				port,
				queue,
				(uint16_t) app.nic_rx_ring_size,
				socket,
				&rx_conf,
				pool);
			if (ret < 0) {
				rte_panic("Cannot init RX queue %u for port %u (%d)\n",
					(unsigned) queue,
					(unsigned) port,
					ret);
			}
		}

		/* Init TX queues */
		if (app.nic_tx_port_mask[port] == 1) {
			app_get_lcore_for_nic_tx(port, &lcore);
			socket = rte_lcore_to_socket_id(lcore);
			printf("Initializing NIC port %u TX queue 0 ...\n",
				(unsigned) port);
			ret = rte_eth_tx_queue_setup(
				port,
				0,
				(uint16_t) app.nic_tx_ring_size,
				socket,
				&tx_conf);
			if (ret < 0) {
				rte_panic("Cannot init TX queue 0 for port %d (%d)\n",
					port,
					ret);
			}
		}

		/* Start port */
		ret = rte_eth_dev_start(port);
		if (ret < 0) {
			rte_panic("Cannot start port %d (%d)\n", port, ret);
		}
	}

	check_all_ports_link_status(APP_MAX_NIC_PORTS, (~0x0));
}

// Initialize the hash tables used for binary search
static void app_init_bst_hash_tables_worst(void) {
  printf("=== Initializing binary search hash tables === \n");

#ifdef SIPHASH
#define FWD_KEYLEN 16
  static uint8_t k[FWD_KEYLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
#endif

  // Load prefixes to hash tables
  char * name_file = app.file_name;
  printf("file name = %s\n", name_file);

  char load_name_file[100];
  strcpy(load_name_file, name_file);
  char load_file_suffix[] = ".txt";
  strcat(load_name_file, load_file_suffix);
  printf("Load file = %s\n", load_name_file);

  Name_Entry_t * name_list;
  int line_count = load_prefixes_with_line_count(&name_list, load_name_file, app.line_count);
  printf("Number of lines: %d\n", line_count);

  fflush(stdout);

  int ht_size[16]; // hash_table_size
  int ii = 0;
  for (ii = 1; ii < 16; ii++){
    ht_size[ii] = line_count / 8;
  }

#ifdef Three_LEVEL
  // Create 7 hash tables
  // Populate only levels 4, 6, and 7
  int ht_min_size = 16;

  // Create 7 hash tables
  char name[32];
  snprintf(name, sizeof(name), "hash tables");
  struct Hash_Table ** hts[2];
  hts[0] = rte_malloc_socket(name, 64, sizeof(struct Hash_Table *) * 8, 0);
  hts[0][1] = hash_table_init_socket(ht_min_size, 0, 0, 0);
  hts[0][2] = hash_table_init_socket(ht_min_size, 1, 3, 0);
  hts[0][3] = hash_table_init_socket(ht_min_size, 0, 0, 0);
  hts[0][4] = hash_table_init_socket(2 * ht_size[4], 2, 6, 0);
  hts[0][5] = hash_table_init_socket(ht_min_size, 0, 0, 0);
  hts[0][6] = hash_table_init_socket(2 * ht_size[6], 5, 7, 0);
  hts[0][7] = hash_table_init_socket(2 * ht_size[7], 0, 0, 0);


#ifdef DUAL_SOCKETS // If the data structures are duplicated across two NUMA nodes.
  hts[1] = rte_malloc_socket(name, 64, sizeof(struct Hash_Table *) * 8, 1);
  hts[1][1] = hash_table_init_socket(ht_min_size, 0, 0, 1);
  hts[1][2] = hash_table_init_socket(ht_min_size, 1, 3, 1);
  hts[1][3] = hash_table_init_socket(ht_min_size, 0, 0, 1);
  hts[1][4] = hash_table_init_socket(2 * ht_size[4], 2, 6, 1);
  hts[1][5] = hash_table_init_socket(ht_min_size, 0, 0, 1);
  hts[1][6] = hash_table_init_socket(2 * ht_size[6], 5, 7, 1);
  hts[1][7] = hash_table_init_socket(2 * ht_size[7], 0, 0, 1);
#endif

#endif // Three_LEVEL

#ifdef Four_LEVEL
  //Create 15 hash tables
  // Populate only levels 8, 12, 14, 15
  char name[32];
  snprintf(name, sizeof(name), "hash tables four level");
  struct Hash_Table ** hts[2];
  int ht_min_size = 16;
  hts[0] = rte_malloc_socket(name, 64, sizeof(struct Hash_Table *) * 16, 0);
  hts[0][1] = hash_table_init_socket(ht_min_size, 0, 0, 0);
  hts[0][2] = hash_table_init_socket(ht_min_size, 1, 3, 0);
  hts[0][3] = hash_table_init_socket(ht_min_size, 0, 0, 0);
  hts[0][4] = hash_table_init_socket(ht_min_size, 2, 6, 0);
  hts[0][5] = hash_table_init_socket(ht_min_size, 0, 0, 0);
  hts[0][6] = hash_table_init_socket(ht_min_size, 5, 7, 0);
  hts[0][7] = hash_table_init_socket(ht_min_size, 0, 0, 0);
  hts[0][8] = hash_table_init_socket(2 * ht_size[8], 4, 12, 0);
  hts[0][9] = hash_table_init_socket(ht_min_size, 0, 0, 0);
  hts[0][10] = hash_table_init_socket(ht_min_size, 9, 11, 0);
  hts[0][11] = hash_table_init_socket(ht_min_size, 0, 0, 0);
  hts[0][12] = hash_table_init_socket(2 * ht_size[12], 10, 14, 0);
  hts[0][13] = hash_table_init_socket(ht_min_size, 0, 0, 0);
  hts[0][14] = hash_table_init_socket(2 * ht_size[14], 13, 15, 0);
  hts[0][15] = hash_table_init_socket(2 * ht_size[15], 0, 0, 0);
#endif

#define MAX_BLOCK 8 // 8 GB

  int current_index_init = 0;
  void * base[MAX_BLOCK];
  void * block_end[MAX_BLOCK];
  void * next_free;
  void * mem_end;
  uint64_t total_str_mem = 0;

#ifdef DUAL_SOCKETS
  int current_index_init2 = 0;
  void * base2[MAX_BLOCK];
  void * block_end2[MAX_BLOCK];
  void * next_free2;
  void * mem_end2;
#endif

  uint64_t size_hex = 1000000000; // 1 GB
  size_t mem_size = (size_t)(size_hex);

  int p;
  for (p = 0; p < MAX_BLOCK; p++) {

#ifdef RTE_HUGEPAGE
    base[p] = rte_zmalloc(NULL, mem_size, CACHE_LINE);
#ifdef DUAL_SOCKETS
    base2[p] = rte_zmalloc_socket(NULL, mem_size, CACHE_LINE, 1); // Allocate from Socket 1
#endif
#else
    if (posix_memalign((void *)&(base[p]), CACHE_LINE, mem_size) != 0) {
      printf("posix_memalign string memory allocation failed\n");
      exit(1);
    }
#endif

  if (base[p] == NULL) {
      printf("rte_malloc_socket for string memory failed\n");
      rte_malloc_dump_stats(stdout, NULL);
      exit(1);
    }
    assert( ((uint64_t)base[p] % CACHE_LINE) == 0);
    block_end[p] = (void *) ((uint64_t)base[p] + size_hex);

#ifdef DUAL_SOCKETS
  if (base2[p] == NULL) {
      printf("rte_malloc_socket for string memory failed\n");
      rte_malloc_dump_stats(stdout, NULL);
      exit(1);
    }
    assert( ((uint64_t)base2[p] % CACHE_LINE) == 0);
    block_end2[p] = (void *) ((uint64_t)base2[p] + size_hex);

#endif
  }
  current_index_init = 0;
  next_free = base[current_index_init];
  mem_end = block_end[current_index_init];

#ifdef DUAL_SOCKETS
  current_index_init2 = 0;
  next_free2 = base2[current_index_init2];
  mem_end2 = block_end2[current_index_init2];
#endif
  // rte_malloc_dump_stats(stdout, NULL);

#ifdef Three_LEVEL
  int lookup_line_count = line_count / 3;
#endif

#ifdef Four_LEVEL
  int lookup_line_count = line_count / 4;
#endif

  int insertion_phase_1 = line_count - lookup_line_count;
  printf("insertion_phase_1 = %d\n", insertion_phase_1);

#ifdef SIPHASH
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
  uint64_t len;
#endif

  int i = 0, j = 0;
  int lens[32];
  char * prefix = NULL;
  char * pch = NULL;
  uint8_t max_comp = 0;
  uint64_t hash_value = 0;

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  //     Insertion Phase ONE (do not store strings)
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  for (i = line_count - insertion_phase_1; i < line_count; i++) {

    max_comp = 1;
    prefix = name_list[i].name;
    prefix = (char*)(prefix + NAME_OFFSET); // type + length

#ifdef SIPHASH
    uint8_t * in = (uint8_t *)prefix;
    uint64_t v0 = v0_s;
    uint64_t v1 = v1_s;
    uint64_t v2 = v2_s;
    uint64_t v3 = v3_s;
#endif

    pch=strchr(prefix,'/');
    while (pch!=NULL) {
      lens[max_comp] = pch-prefix+1;
      max_comp++;
      pch=strchr(pch+1,'/');

      if (max_comp >= MAX_COMP_NUM)
        break;
    }

    if (max_comp > MAX_COMP_NUM) max_comp = MAX_COMP_NUM;

    j = 1;
    for (j = 1; j < max_comp; j++) {

#ifdef Three_LEVEL
      if (j == 1 || j == 2 || j == 3 || j == 5) {
        continue;
      }
#endif

#ifdef Four_LEVEL
      if (j <= 7 || j == 9 || j == 10 || j == 11 || j == 13) {
        continue;
      }
#endif

#ifdef CRCHASH
      hash_value = crc_hash_init(prefix, lens[j]);
#endif

#ifdef CITYHASH
      hash_value = CityHash64(prefix, lens[j]);
#endif

#ifdef SIPHASH
      len = lens[j];
      const uint8_t *end = (uint8_t *)prefix + len - ( len % sizeof( uint64_t ));
      siphash_step(&v0, &v1, &v2, &v3, &in, end, len, &hash_value);
#endif

      hash_table_insert((Hash_Table_t *)hts[0][j], prefix, lens[j], hash_value, NULL);
#ifdef DUAL_SOCKETS
      hash_table_insert((Hash_Table_t *)hts[1][j], prefix, lens[j], hash_value, NULL);
#endif
    }
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  //     Free random name list
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  free_prefixes(name_list, line_count);

  char insert_name_file[100];
  strcpy(insert_name_file, name_file);
  char insert_file_suffix[] = ".prefix.txt";
  strcat(insert_name_file, insert_file_suffix);
  line_count = load_prefixes(&name_list, insert_name_file);
  printf("Insertion phase 2 file = %s\n", insert_name_file);
  printf("Number of lines: %d\n", line_count);


  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  //     Insertion Phase TWO (STORE STRINGS)
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  for (j = 1; j < MAX_COMP_NUM; j++) {

#ifdef Three_LEVEL
      if (j == 1 || j == 2 || j == 3 || j == 5) {
        continue;
      }
#endif

#ifdef Four_LEVEL
      if (j <= 7 || j == 9 || j == 10 || j == 11 || j == 13) {
        continue;
      }
#endif

    for (i = 0; i < line_count; i++) {
      max_comp = 1;
      prefix = name_list[i].name + NAME_OFFSET;

      pch=strchr(prefix,'/');
      while (pch!=NULL) {
        lens[max_comp] = pch-prefix+1;
        max_comp++;
        pch=strchr(pch+1,'/');

        if (max_comp >= MAX_COMP_NUM)
          break;
      }
      assert(max_comp <= MAX_COMP_NUM);

#ifdef CRCHASH
      hash_value = crc_hash_init(prefix, lens[j]);
#endif

  #ifdef CITYHASH
      hash_value = CityHash64(prefix, lens[j]);
  #endif

  #ifdef SIPHASH
      uint8_t * in = (uint8_t *)prefix;
      uint64_t v0 = v0_s;
      uint64_t v1 = v1_s;
      uint64_t v2 = v2_s;
      uint64_t v3 = v3_s;
      len = lens[j];
      const uint8_t *end = (uint8_t *)prefix + len - ( len % sizeof( uint64_t ));
      siphash_step(&v0, &v1, &v2, &v3, &in, end, len, &hash_value);
  #endif

      int level = -1;
      switch(j) {
        case 4:
          level = 0;
          break;
        case 6:
          level = 1;
          break;
        case 7:
          level = 2;
          break;
        case 8:
          level = 0;
          break;
        case 12:
          level = 1;
          break;
        case 14:
          level = 2;
          break;
        case 16:
          level = 3;
          break;
        default:
          level = -1;
      }

      assert(level != -1);

      hash_table_insert_verify((Hash_Table_t *)hts[0][j], prefix, lens[j], hash_value, next_free, level);
      total_str_mem += (1 + (lens[j] + FWD_INFO_SIZE) / 16) * 16;

      next_free = (void *)((uint64_t)next_free + (1 + (lens[j] + FWD_INFO_SIZE) / 16) * 16);
      if ( (uint64_t)next_free >= (uint64_t)mem_end) {
        ++current_index_init;
        if (current_index_init >= MAX_BLOCK) {
          printf("Error, current index init greater than max block\n");
          printf("Total string memory = %.2f GB\n", total_str_mem / 1024.0 / 1024.0 / 1024.0);
          exit(-1);
        }
        printf("current_index_init = %d\n", current_index_init);
        next_free = base[current_index_init];
        mem_end = block_end[current_index_init];
      }

      assert((uint64_t)next_free % 16 == 0);

      if ((uint64_t)(next_free) >= (uint64_t)(mem_end)) {
        printf("Total string memory = %.2f GB\n", total_str_mem / 1024.0 / 1024.0 / 1024.0);
      }

      assert( (uint64_t)(next_free) < (uint64_t)(mem_end) );

#ifdef DUAL_SOCKETS
      hash_table_insert_verify((Hash_Table_t *)hts[1][j], prefix, lens[j], hash_value, next_free2, level);

      next_free2 = (void *)((uint64_t)next_free2 + (1 + (lens[j] + FWD_INFO_SIZE) / 16) * 16);
      if ( (uint64_t)next_free2 >= (uint64_t)mem_end2) {
        ++current_index_init2;
        if (current_index_init2 >= MAX_BLOCK) {
          printf("Error, current index init greater than max block\n");
          printf("Total string memory = %.2f GB\n", total_str_mem / 1024.0 / 1024.0 / 1024.0);
          exit(-1);
        }
        printf("current_index_init2 = %d\n", current_index_init2);
        next_free2 = base[current_index_init2];
        mem_end2 = block_end[current_index_init2];
      }

      assert((uint64_t)next_free2 % 16 == 0);

      if ((uint64_t)(next_free2) >= (uint64_t)(mem_end2)) {
        printf("Total string memory = %.2f GB\n", total_str_mem / 1024.0 / 1024.0 / 1024.0);
      }

      assert( (uint64_t)(next_free2) < (uint64_t)(mem_end2) );
#endif

    }
  }

  printf("Total string memory = %.2f GB\n", total_str_mem / 1024.0 / 1024.0 / 1024.0);

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  //     Free sequential name list
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  free_prefixes(name_list, line_count);

  char lookup_name_file[100];
  strcpy(lookup_name_file, name_file);
  char lookup_file_suffix[] = ".prefix.shuf";
  strcat(lookup_name_file, lookup_file_suffix);

#ifdef DUAL_SOCKETS
  Name_Entry_t * lookup_name_list[2];
  line_count = load_prefixes_socket(&lookup_name_list[0], lookup_name_file, 0);
  line_count = load_prefixes_socket(&lookup_name_list[1], lookup_name_file, 1);
#else
  line_count = load_prefixes(&name_list, lookup_name_file);
#endif
  printf("Lookup file = %s, line_count = %d\n", lookup_name_file, line_count);

  unsigned lcore;
  for (lcore = 0; lcore < APP_MAX_LCORES; lcore ++) {
    if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER) {
#ifdef DUAL_SOCKETS
    int socket = rte_lcore_to_socket_id(lcore);
    app.lcore_params[lcore].io.rx.name_list = lookup_name_list[socket];
#else
      app.lcore_params[lcore].io.rx.name_list = name_list;
#endif
      app.lcore_params[lcore].io.rx.line_count = line_count;
      continue;
    }

    int socket = 0;
#ifdef DUAL_SOCKETS
    socket = rte_lcore_to_socket_id(lcore);
#endif
    app.lcore_params[lcore].worker.hts = hts[socket];
  }
}

void
app_init(void)
{
	app_assign_worker_ids();
	app_init_mbuf_pools();

	// Initialize the binary search hash tables
	app_init_bst_hash_tables_worst();

	// app_init_lpm_tables();
	app_init_rings_rx();
	app_init_rings_tx();
	app_init_nics();
}
