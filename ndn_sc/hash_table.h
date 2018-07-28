/*-
 *  BSD LICENSE
 *  Copyright (c) 2014-2015, Washington University in St. Louis.
 *  All rights reserved.
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

#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <assert.h>
#include <stddef.h>
#include <inttypes.h>

#include <rte_memcpy.h>
#include <rte_malloc.h>

#include "debug.h"
#include "city.h"
#include "rdtsc.h"
#include "fwd_info.h"
#include "utils.h"

#define CACHE_LINE 64         // Memory is allocated on cache_line sized boundaries.
#define BUCKET_SIZE 7         // The number of fingerprint entries in each hash bucket.

#define MULTI_BLOCK_HT 64     // At most 64 blocks
#define HT_BLOCK_SIZE 1024 * 16 // 16 million buckets, 128 million entries // changed block size to 16 thousand buckets

// Fingerprint entry structure
typedef struct FP_Addr{
  uint64_t fp: 20;
  uint64_t addr: 44;
}FP_Addr_t;

// Hash bucket structure
typedef struct Hash_Entry{
  uint64_t occupied: 7;
  uint64_t collided: 7;
  uint64_t leaf: 7;
  uint64_t next : 42; // Bucket will align at 64 byte boundary (6 bits)
  uint64_t reserved : 1; // 1 bit is unused
  FP_Addr_t fp_addrs[BUCKET_SIZE];
} __attribute__ ((aligned(CACHE_LINE))) Hash_Entry_t;

// Hash table structure
typedef struct Hash_Table{
  uint32_t size;
  uint32_t item_number;
  uint32_t capacity;
  uint32_t block_size;
  uint32_t max_capacity;
  uint32_t next_free;
  uint32_t insertion_collision;
  uint64_t lookup_false_positive;
#if MULTI_BLOCK_HT
  Hash_Entry_t * buckets[MULTI_BLOCK_HT];
#else
  Hash_Entry_t * buckets;
#endif
  void * fwd_db;
  int left;  // Left subtree root hash table index
  int right; // Right subtree root hash table index
} Hash_Table_t;

// Initialize the hash table
Hash_Table_t * hash_table_init(int size, int left, int right);

// Destroy an existing hash table.
void
hash_table_destroy(Hash_Table_t * ht);

// Initialize the hash table with the specified NUMA node ID.
Hash_Table_t * hash_table_init_socket(int size, int left, int right, int socket);

// Hash lookup that verifies only fingerprints
int
hash_table_lookup(Hash_Table_t * ht, char* key, int len, uint64_t hash_value, char ** addr_entry);

// Hash lookup that verifies strings at each step
int
hash_table_lookup_verify(Hash_Table_t * ht, char* key, int len, uint64_t hash_value, char ** addr_entry);

// Insert an item into the specified hash table.
int
hash_table_insert(Hash_Table_t * ht, char* key, int len, uint64_t hash_value, char* fwd_info);

// Insert an item into the specified hash table
int
hash_table_insert_verify(Hash_Table_t * ht, char* key, int len, uint64_t hash_value, void * fwd_info, int level);

// Dump the information stored in the hash table
void
hash_table_dump(Hash_Table_t* ht);

// Basic hash table function tests.
void
hash_table_uint_test(void);

#endif
