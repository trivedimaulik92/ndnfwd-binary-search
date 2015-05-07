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

#include "hash_table.h"

extern int debug;

#define RTE_HUGEPAGE // Using large pages
#define HT_CHAIN_PREFETCH // Prefetch the chained hash bucket in case of bucket overflow

Hash_Table_t *
hash_table_init(int size, int left, int right){
  // if(debug > 2) dbgm();
  printf("hash_table_init, size = %d\n", size);

#ifdef RTE_HUGEPAGE
  Hash_Table_t * ht = rte_zmalloc("ht", sizeof(Hash_Table_t), CACHE_LINE); // No specified NUMA socket.
#else
  Hash_Table_t * ht = malloc(sizeof(Hash_Table_t));
#endif

  // Initialize hash table parameters
  ht->size = size;
  ht->item_number = 0;
  ht->capacity = size;

  int max_capacity = (int)((double)size * 1.1);   // Preallocate additional 10% buckets to handle overflow
  ht->max_capacity = max_capacity;

  ht->next_free = size; // the starting index of the additional buckets
  ht->insertion_collision = 0;
  ht->lookup_false_positive = 0;

#if MULTI_BLOCK_HT
  ht->block_size = HT_BLOCK_SIZE; // Allocate 16 million buckets each time (128 million HT entries)
#else
  ht->block_size = max_capacity;
#endif

  ht->left = left;
  ht->right = right;

  assert(sizeof(Hash_Entry_t) % CACHE_LINE == 0);

#ifdef RTE_HUGEPAGE
  printf("Allocating Hash Table with large pages\n");
  char name[32];
  snprintf(name, sizeof(name), "hash table");

#if MULTI_BLOCK_HT
  printf("HT with multiple blocks\n");

  int i = 0;
  for (i = 0; i < MULTI_BLOCK_HT; i++) {
    ht->buckets[i] = NULL;
  }

  i = 0;
  int size_to_allocate = ht->max_capacity;
  while(size_to_allocate >= (int)ht->block_size) {
    // printf("size to allocate = %d, ht->block_size = %d\n", size_to_allocate, ht->block_size);

    ht->buckets[i] = (Hash_Entry_t *)rte_zmalloc_socket(name, sizeof(Hash_Entry_t) * (ht->block_size), CACHE_LINE, 0); // socket 0 for now..

    printf("Allocating ht buckets[%d], size = %.f GB...", i, sizeof(Hash_Entry_t) * (ht->block_size) / 1073741824.0);
    if (ht->buckets[i] == NULL) {
      printf("failed\n");
      exit(-1);
    } else {
      printf("succeeded\n");
    }

    assert( ((uint64_t)ht->buckets[i] % CACHE_LINE) == 0);
    size_to_allocate -= ht->block_size;
    i++;
  }

  if (size_to_allocate > 0) {
    // Allocate from NUMA socket 0 for now.
    ht->buckets[i] = (Hash_Entry_t *)rte_zmalloc_socket(name, sizeof(Hash_Entry_t) * (size_to_allocate), CACHE_LINE, 0);

    printf("Allocating ht buckets[%d], size = %.f GB...", i, sizeof(Hash_Entry_t) * (ht->block_size) / 1073741824.0);
    if (ht->buckets[i] == NULL) {
      printf("failed\n");
      exit(-1);
    } else {
      printf("succeeded\n");
    }

    assert( ((uint64_t)ht->buckets[i] % CACHE_LINE) == 0);
  }

#else
  printf("HT with a single block\n");
  // Allocate from NUMA socket 0 for now.
  ht->buckets = (Hash_Entry_t *)rte_zmalloc_socket(name, sizeof(Hash_Entry_t) * (max_capacity), CACHE_LINE, 0);

  printf("Allocating ht buckets, size = %.f GB...", sizeof(Hash_Entry_t) * (ht->block_size) / 1073741824.0);
  if (ht->buckets == NULL) {
    printf("failed\n");
    exit(-1);
  } else {
    printf("succeeded\n");
  }
#endif // MULTI_BLOCK_HT

#else
  printf("Allocating Hash Table with posix_memalign\n");

#if MULTI_BLOCK_HT
  printf("HT with multiple blocks\n");

  int i = 0;
  for (i = 0; i < MULTI_BLOCK_HT; i++) {
    ht->buckets[i] = NULL:
  }

  i = 0;
  int size_to_allocate = ht->max_capacity;
  while(size_to_allocate >= (int)ht->block_size) {
    if (posix_memalign((void *)&(ht->buckets[i]), CACHE_LINE, sizeof(Hash_Entry_t) * (ht->block_size)) != 0) {
      printf("posix_memalign failed... \n");
      exit(-1);
    }
    memset(ht->buckets[i], 0, sizeof(Hash_Entry_t) * (ht->block_size));
    assert( ((uint64_t)ht->buckets[i] % CACHE_LINE) == 0);

    size_to_allocate -= ht->block_size;
    if (size_to_allocate <= 0) break;
    i++;
  }
  if (size_to_allocate > 0) {
    if (posix_memalign((void *)&(ht->buckets[i]), CACHE_LINE, sizeof(Hash_Entry_t) * (size_to_allocate)) != 0) {
      printf("posix_memalign failed... \n");
      exit(-1);
    }
    memset(ht->buckets[i], 0, sizeof(Hash_Entry_t) * size_to_allocate);
    assert( ((uint64_t)ht->buckets[i] % CACHE_LINE) == 0);
  }

#else
  printf("HT with a single block\n");
  if (posix_memalign((void *)&(ht->buckets), CACHE_LINE, sizeof(Hash_Entry_t) * (max_capacity)) != 0) {
    printf("posix_memalign failed... \n");
    exit(-1);
  }
  memset(ht->buckets, 0, sizeof(Hash_Entry_t) * max_capacity);
  assert( ((uint64_t)ht->buckets % CACHE_LINE) == 0);
#endif

#endif

  return ht;
}


Hash_Table_t *
hash_table_init_socket(int size, int left, int right, int socket){
  printf("HT size = %d, socket = %d\n", size, socket);

  int max_capacity = (int)((double)size * 1.1);
  printf("Max capacity = %d\n", max_capacity);

#ifdef RTE_HUGEPAGE
  Hash_Table_t * ht = rte_zmalloc_socket("ht", sizeof(Hash_Table_t), CACHE_LINE, socket);
#else
  Hash_Table_t * ht = malloc(sizeof(Hash_Table_t));
#endif

  ht->size = size;
  ht->item_number = 0;
  ht->capacity = size;
  ht->max_capacity = max_capacity;
  ht->next_free = size;
  ht->insertion_collision = 0;
  ht->lookup_false_positive = 0;
#if MULTI_BLOCK_HT
  ht->block_size = 1024 * 1024 * 16; // 2^24 16 million entries --> 1GB memory
#else
  ht->block_size = max_capacity;
#endif
  ht->left = left;
  ht->right = right;

  assert(sizeof(Hash_Entry_t) % CACHE_LINE == 0);

#ifdef RTE_HUGEPAGE
  printf("Allocating Hash Table with large pages\n");
  char name[32];
  snprintf(name, sizeof(name), "hash table");

#if MULTI_BLOCK_HT
  printf("HT with multiple blocks\n");

  int i = 0;
  for (i = 0; i < MULTI_BLOCK_HT; i++) {
    ht->buckets[i] = NULL;
  }

  i = 0;
  int size_to_allocate = ht->max_capacity;
  while(size_to_allocate >= (int)ht->block_size) {
    ht->buckets[i] = (Hash_Entry_t *)rte_zmalloc_socket(name, sizeof(Hash_Entry_t) * (ht->block_size), CACHE_LINE, socket); // socket 0 for now..

    printf("Allocating ht buckets[%d], size = %.f GB...", i, sizeof(Hash_Entry_t) * (ht->block_size) / 1073741824.0);
    if (ht->buckets[i] == NULL) {
      printf("failed\n");
      exit(-1);
    } else {
      printf("succeeded\n");
    }

    assert( ((uint64_t)ht->buckets[i] % CACHE_LINE) == 0);
    size_to_allocate -= ht->block_size;
    i++;
  }

  if (size_to_allocate > 0) {
    ht->buckets[i] = (Hash_Entry_t *)rte_zmalloc_socket(name, sizeof(Hash_Entry_t) * (size_to_allocate), CACHE_LINE, socket);

    printf("Allocating ht buckets[%d], size = %.f GB...", i, sizeof(Hash_Entry_t) * (ht->block_size) / 1073741824.0);
    if (ht->buckets[i] == NULL) {
      printf("failed\n");
      exit(-1);
    } else {
      printf("succeeded\n");
    }

    assert( ((uint64_t)ht->buckets[i] % CACHE_LINE) == 0);
  }

#else
  printf("HT with a single block\n");
  ht->buckets = (Hash_Entry_t *)rte_zmalloc_socket(name, sizeof(Hash_Entry_t) * (max_capacity), CACHE_LINE, socket);

  printf("Allocating ht buckets, size = %.f GB...", sizeof(Hash_Entry_t) * (ht->block_size) / 1073741824.0);
  if (ht->buckets == NULL) {
    printf("failed\n");
    exit(-1);
  } else {
    printf("succeeded\n");
  }
#endif // MULTI_BLOCK_HT

#else
  printf("Allocating Hash Table with posix_memalign\n");

#if MULTI_BLOCK_HT
  printf("HT with multiple blocks\n");

  int i = 0;
  for (i = 0; i < MULTI_BLOCK_HT; i++) {
    ht->buckets[i] = NULL:
  }

  i = 0;
  int size_to_allocate = ht->max_capacity;
  while(size_to_allocate >= (int)ht->block_size) {
    if (posix_memalign((void *)&(ht->buckets[i]), CACHE_LINE, sizeof(Hash_Entry_t) * (ht->block_size)) != 0) {
      printf("posix_memalign failed... \n");
      exit(-1);
    }
    memset(ht->buckets[i], 0, sizeof(Hash_Entry_t) * (ht->block_size));
    assert( ((uint64_t)ht->buckets[i] % CACHE_LINE) == 0);

    size_to_allocate -= ht->block_size;
    if (size_to_allocate <= 0) break;
    i++;
  }
  if (size_to_allocate > 0) {
    if (posix_memalign((void *)&(ht->buckets[i]), CACHE_LINE, sizeof(Hash_Entry_t) * (size_to_allocate)) != 0) {
      printf("posix_memalign failed... \n");
      exit(-1);
    }
    memset(ht->buckets[i], 0, sizeof(Hash_Entry_t) * size_to_allocate);
    assert( ((uint64_t)ht->buckets[i] % CACHE_LINE) == 0);
  }

#else
  printf("HT with a single block\n");
  if (posix_memalign((void *)&(ht->buckets), CACHE_LINE, sizeof(Hash_Entry_t) * (max_capacity)) != 0) {
    printf("posix_memalign failed... \n");
    exit(-1);
  }
  memset(ht->buckets, 0, sizeof(Hash_Entry_t) * max_capacity);
  assert( ((uint64_t)ht->buckets % CACHE_LINE) == 0);
#endif

#endif

  return ht;
}

inline int
hash_table_lookup(Hash_Table_t * ht, char* key, int len, uint64_t hash_value, char ** addr_entry){
  // if(debug > 2) dbgm();

  uint32_t loc = (hash_value >> 32) % ht->size;
  uint32_t fp = hash_value & 0xfffff; // 20 bits

#if MULTI_BLOCK_HT
  Hash_Entry_t * cur_bucket = &ht->buckets[loc >> 24][loc & 0xffffff];
#else
  Hash_Entry_t * cur_bucket = &ht->buckets[loc];
#endif

  int i = 0;
  uint32_t occupied_bit = 1;

  while(cur_bucket != NULL) {

#ifdef HT_CHAIN_PREFETCH
    if (cur_bucket->next) { // prefetch the chained hash bucket
      __builtin_prefetch((void *)((uint64_t)cur_bucket->next << 6));
    }
#endif
    occupied_bit = 1;

    for (i = 0; i < BUCKET_SIZE; i++) {
      // For each hash table entry in the bucket
      if ((cur_bucket->occupied & occupied_bit) > 0) {
        if (cur_bucket->fp_addrs[i].fp == fp) {
          // then compare the strings
          if ( (cur_bucket->collided & occupied_bit) > 0) {

            if ( (cur_bucket->fp_addrs[i].addr != 0) &&
                    (memcmp( (char *)( (uint64_t)(cur_bucket->fp_addrs[i].addr) << 4) + FWD_INFO_SIZE, key, len) == 0)) {
              *addr_entry = (char *)( (uint64_t)(cur_bucket->fp_addrs[i].addr) << 4);
              return 1; // matched
            } else {
              occupied_bit <<= 1;
              continue;
            }
          } else {
            *addr_entry = (char *)((uint64_t)(cur_bucket->fp_addrs[i].addr) << 4);
            return 1;
          }
        }
      }
      occupied_bit <<= 1;
    } // for (i < BUCKET_SIZE)

    cur_bucket = (Hash_Entry_t *)((uint64_t)cur_bucket->next << 6);
  } // while

  return 0;
}

inline int
hash_table_lookup_verify(Hash_Table_t * ht, char* key, int len, uint64_t hash_value, char ** addr_entry){
  // if(debug > 2) dbgm();

  uint32_t loc = (hash_value >> 32) % ht->size;
  uint32_t fp = hash_value & 0xfffff; // 20 bits

#if MULTI_BLOCK_HT
  Hash_Entry_t * cur_bucket = &ht->buckets[loc >> 24][loc & 0xffffff];
#else
  Hash_Entry_t * cur_bucket = &ht->buckets[loc];
#endif

  int i = 0;
  uint32_t occupied_bit = 1;

  while(cur_bucket != NULL) {

#ifdef HT_CHAIN_PREFETCH
    if (cur_bucket->next) { // prefetch the chained hash bucket
      __builtin_prefetch((void *)((uint64_t)cur_bucket->next << 6));
    }
#endif
    occupied_bit = 1;

    for (i = 0; i < BUCKET_SIZE; i++) {
      if ((cur_bucket->occupied & occupied_bit) > 0) {
        if (cur_bucket->fp_addrs[i].fp == fp) {
          // then compare the strings
          if ( (cur_bucket->collided & occupied_bit) > 0) {
            if ( (cur_bucket->fp_addrs[i].addr != 0) &&
                    (memcmp( (char *)( (uint64_t)(cur_bucket->fp_addrs[i].addr) << 4) + FWD_INFO_SIZE, key, len) == 0)) {
              *addr_entry = (char *)( (uint64_t)(cur_bucket->fp_addrs[i].addr) << 4);
              return 1; // matched
            } else {
              occupied_bit <<= 1;
              continue;
            }
          } else {
            assert(cur_bucket->fp_addrs[i].addr != 0);
            if (memcmp( (char *)( ((uint64_t)(cur_bucket->fp_addrs[i].addr) << 4) + FWD_INFO_SIZE), key, len) == 0) {
              *addr_entry = (char *)((uint64_t)(cur_bucket->fp_addrs[i].addr) << 4);
              return 1;
            } else {
              ht->lookup_false_positive++;
              return 0;
            }
          }
        }
      }
      occupied_bit <<= 1;
    } // for (i < BUCKET_SIZE)

    cur_bucket = (Hash_Entry_t *)((uint64_t)cur_bucket->next << 6);
  } // while

  return 0;
}


// preallocated name prefix entry
int
hash_table_insert(Hash_Table_t * ht, char* key, int len, uint64_t hash_value, char * fwd_info){
  // if(debug > 2) dbgm();

  uint32_t loc = (hash_value >> 32) % ht->size;
  uint32_t fp = hash_value & 0xfffff; // 20 bits

  uint32_t occupied_bit = 1;
  uint32_t empty_occupied_mask = 0;
  uint32_t empty_index = 0;
  uint32_t empty_found = 0;
  uint32_t collision_flag = 0;

#if MULTI_BLOCK_HT
  Hash_Entry_t * cur_bucket = &ht->buckets[loc >> 24][loc & 0xffffff]; // Each block has 128 million (2^24) entries
#else
  Hash_Entry_t * cur_bucket = &ht->buckets[loc];
#endif

  Hash_Entry_t * valid_bucket = NULL;
  int i = 0;

  while(cur_bucket != NULL) {
    occupied_bit = 1;
    for (i = 0; i < BUCKET_SIZE; i++) {
      if ((cur_bucket->occupied & occupied_bit) > 0) {
        // if this slot is taken, then make sure this is not a duplication insertion
        if (cur_bucket->fp_addrs[i].fp == fp) {
          // then compare the strings
          if ( (cur_bucket->fp_addrs[i].addr != 0)
            && (memcmp( (char *)( (uint64_t)(cur_bucket->fp_addrs[i].addr) << 4) + FWD_INFO_SIZE, key, len) == 0)) {
            return 1; // duplicate insertion
          } else {
            // We have a name prefix collision
            collision_flag = 1;
            // Mark collision bit for the current entry, and then keep searching
            cur_bucket->collided |= occupied_bit;
            ht->insertion_collision++;
          }
        }
      } else {
        // empty slot found
        if (empty_found == 0) {
          empty_occupied_mask = occupied_bit;
          empty_index = i;
          empty_found = 1;
        }
      }
      occupied_bit <<= 1;
    } // for (i < BUCKET_SIZE)
    valid_bucket = cur_bucket;
    cur_bucket = (Hash_Entry_t *)( (uint64_t)cur_bucket->next << 6);
  } // while

  // After examining all the available hash buckets at index = loc
  if (empty_found == 0) {
    // Allocate a new hash bucket
#if MULTI_BLOCK_HT
    uint32_t offset = ht->next_free & 0xffffff;
    uint32_t block_index = ht->next_free >> 24; // Each block has 128 million (2^24) entries
    Hash_Entry_t * new_bucket = &(ht->buckets[block_index][offset]);
#else
    Hash_Entry_t * new_bucket = &(ht->buckets[ht->next_free]);
#endif
    bzero(new_bucket, sizeof(Hash_Entry_t));

    ht->capacity++;
    ht->next_free++;

    if (ht->next_free >= ht->max_capacity) {
      printf("HT ran out of dynamic buckets...\n");
      exit(-1);
    }

    // Update the chaining address of the previous bucket
    valid_bucket->next = ((uint64_t)new_bucket >> 6);

    // The first slot in the newly assigned hash bucket should always be empty
    valid_bucket = new_bucket;
    empty_index = 0;
    empty_found = 1;
    empty_occupied_mask = 1;
  }

  assert(empty_found == 1);

  // Insert a new rule to the empty slot
  valid_bucket->occupied |= empty_occupied_mask;

  if (collision_flag) {
    valid_bucket->collided |= empty_occupied_mask;
    ht->insertion_collision++;
  }

  valid_bucket->fp_addrs[empty_index].fp = fp;
  valid_bucket->fp_addrs[empty_index].addr = ((uint64_t)fwd_info >> 4);
  ht->item_number++;

  return 0;
}

// Free the allocated memory
void
hash_table_destroy(Hash_Table_t * ht) {

#ifdef MULTI_BLOCK_HT
  int i = 0;
  for (i = 0; i < MULTI_BLOCK_HT; i++) {
    if (ht->buckets[i]) {
#ifdef RTE_HUGEPAGE
      rte_free(ht->buckets[i]);
#else
      free(ht->buckets[i]);
#endif
    }
  }
#else // if not MULTI_BLOCK_HT

#ifdef RTE_HUGEPAGE
  rte_free(ht->buckets);
#else
  free(ht->buckets);
#endif

#endif

#ifdef RTE_HUGEPAGE
  rte_free(ht);
#else
  free(ht);
#endif
}

// copy name prefix string entry
int
hash_table_insert_verify(Hash_Table_t * ht, char* key, int len, uint64_t hash_value, void * fwd_info, int level){
  // if(debug > 2) dbgm();

  uint32_t loc = (hash_value >> 32) % ht->size;
  uint32_t fp = hash_value & 0xfffff; // 20 bits

#if MULTI_BLOCK_HT
  Hash_Entry_t * cur_bucket = &ht->buckets[loc >> 24][loc & 0xffffff]; // Each block has 128 million (2^24) entries
#else
  Hash_Entry_t * cur_bucket = &ht->buckets[loc];
#endif

  uint32_t occupied_bit = 1;
  uint32_t empty_occupied_mask = 0;
  uint32_t empty_index = 0;
  uint32_t empty_found = 0;
  uint32_t collision_flag = 0;

  Hash_Entry_t * valid_bucket = NULL;
  int i = 0;

  while(cur_bucket != NULL) {
    occupied_bit = 1;
    for (i = 0; i < BUCKET_SIZE; i++) {
      if ((cur_bucket->occupied & occupied_bit) > 0) {
        // if this slot is taken, then make sure this is not a duplicate insertion
        if (cur_bucket->fp_addrs[i].fp == fp) {
          // then compare the strings
          if ( (cur_bucket->fp_addrs[i].addr != 0) && (memcmp( (char *)( (uint64_t)(cur_bucket->fp_addrs[i].addr) << 4) + FWD_INFO_SIZE, key, len) == 0)) {
            return 1; // matched
          } else {
            // We have a collision
            collision_flag = 1;
            // Mark collision bit for the current entry
            cur_bucket->collided |= occupied_bit;
            ht->insertion_collision++;
          }
        }
      } else {
        // empty slot found
        if (empty_found == 0) {
          empty_occupied_mask = occupied_bit;
          empty_index = i;
          empty_found = 1;
        }
      }
      occupied_bit <<= 1;
    } // for (i < BUCKET_SIZE)
    valid_bucket = cur_bucket;
    cur_bucket = (Hash_Entry_t *)( (uint64_t)cur_bucket->next << 6);
  } // while

  if (empty_found == 0) {
    // Allocate a new hash bucket
#if MULTI_BLOCK_HT
    uint32_t offset = ht->next_free & 0xffffff;
    uint32_t block_index = ht->next_free >> 24; // Each block has 128 million (2^24) entries
    Hash_Entry_t * new_bucket = &(ht->buckets[block_index][offset]);
#else
    Hash_Entry_t * new_bucket = &(ht->buckets[ht->next_free]);
#endif
    bzero(new_bucket, sizeof(Hash_Entry_t));
    ht->capacity++;
    ht->next_free++;
    if (ht->next_free >= ht->max_capacity) {
      printf("HT running out of dynamic buckets...\n");
      exit(1);
    }
    valid_bucket->next = ((uint64_t)new_bucket >> 6);

    valid_bucket = new_bucket;
    empty_index = 0;
    empty_found = 1;
    empty_occupied_mask = 1;
  }

  valid_bucket->occupied |= empty_occupied_mask;
  if (collision_flag) {
    valid_bucket->collided |= empty_occupied_mask;
    ht->insertion_collision++;
  }

  valid_bucket->fp_addrs[empty_index].fp = fp;

#ifdef RTE_HUGEPAGE
  rte_memcpy((char *)fwd_info + FWD_INFO_SIZE, key, len);
#else
  memcpy((char *)fwd_info + FWD_INFO_SIZE, key, len);
#endif

  Fwd_Info_Entry_t * fwd_info_bucket = (Fwd_Info_Entry_t *)fwd_info;
  fwd_info_bucket->out_ports[level] = 1;
  fwd_info_bucket++;

  valid_bucket->fp_addrs[empty_index].addr = ((uint64_t)fwd_info >> 4);
  ht->item_number++;

  return 0;
}

void
hash_table_dump(Hash_Table_t* ht){
  printf("------------------------------------------\n");
  printf("hash table size = %u\n", ht->size);
  printf("hash table cap  = %u\n", ht->capacity);
  printf("hash table item = %u\n", ht->item_number);
  printf("hash table insertion collision = %u\n", ht->insertion_collision);
  printf("hash table lookup false positive = %" PRIu64 "\n", ht->lookup_false_positive);
}
