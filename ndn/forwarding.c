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

#include <rte_malloc.h>

#include "forwarding.h"
#include "siphash24.h"
#include "city.h"

#if PAPI_PROF
  #include <papi.h>
#endif

extern int debug;
uint64_t match_result[16];
int g_run_count = 1;

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#ifdef SIPHASH
#define FWD_KEYLEN 16
static uint8_t k[FWD_KEYLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
#endif

#if PAPI_PROF
void handle_error (int retval)
{
     printf("PAPI error %d\n", retval);
     exit(1);
}
#endif


#if G_HASH_CAL_PROF
  uint64_t g_h_start = 0, g_h_end = 0;
  static uint64_t g_h_total = 0;
  static uint64_t g_h_total_count = 0;
#endif

// Stats
uint64_t basic_bst_false_positive = 0;
uint64_t total_str_mem = 0;

int
load_prefixes_with_line_count(Name_Entry_t ** name_list_p, char * file_name, int line_count) {

  FILE * fp;
  char line[200];

  Name_Entry_t * name_list;

  if (posix_memalign((void **)(&(name_list)), CACHE_LINE, sizeof(Name_Entry_t) * line_count) != 0) {
    printf("Failed to allocate name list\n");
    exit(1);
  }

  fp = fopen(file_name, "r");

  int i = 0;
  int len = 0;
  while(fgets(line, sizeof line, fp) != NULL){
    len = strlen(line);
    memcpy(name_list[i].name, line, len);
    i++;
  }

  fclose(fp);

  *name_list_p = name_list;

  return line_count;
}

int
load_prefixes(Name_Entry_t ** name_list_p, char * file_name) {
  FILE * fp;
  char line[200];

  int line_count = get_line_count(file_name);

  Name_Entry_t * name_list;

  if (posix_memalign((void **)(&(name_list)), CACHE_LINE, sizeof(Name_Entry_t) * line_count) != 0) {
    printf("Failed to allocate name list\n");
    exit(1);
  }

  fp = fopen(file_name, "r");

  int i = 0;
  int len = 0;
  while(fgets(line, sizeof line, fp) != NULL){
    len = strlen(line);
    memcpy(name_list[i].name, line, len);
    i++;
  }

  fclose(fp);

  *name_list_p = name_list;

  return line_count;
}

int
load_prefixes_socket(Name_Entry_t ** name_list_p, char * file_name, int socket) {
  FILE * fp;
  char line[200];

  int line_count = get_line_count(file_name);
  Name_Entry_t * name_list;

  name_list = (Name_Entry_t *)rte_zmalloc_socket(NULL, sizeof(Name_Entry_t) * line_count, CACHE_LINE, socket);
  if (name_list == NULL) {
    printf("Failed to allocate name list at socket %d\n", socket);
    exit(-1);
  }

  fp = fopen(file_name, "r");

  int i = 0;
  int len = 0;
  while(fgets(line, sizeof line, fp) != NULL){
    len = strlen(line);
    memcpy(name_list[i].name, line, len);
    i++;
  }

  fclose(fp);

  *name_list_p = name_list;

  return line_count;
}

int free_prefixes(Name_Entry_t * name_list, int line_count) {
  printf("line_count = %u\n", line_count);

  free(name_list);

  return 0;
}

inline uint16_t
basic_binary_search(Hash_Table_t ** hts, int i, char * query, int * lens, uint64_t * hash_values) {
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

#ifdef VERIFY_MATCHING // Verify string in the end
  if (memcmp(query, best_addr + FWD_INFO_SIZE, lens[best_match]) != 0) {
    basic_bst_false_positive++;
    return basic_binary_search_verify(hts, i, query, lens, hash_values);
  }
#endif

  match_result[best_match]++;

  return ((Fwd_Info_Entry_t *)(best_addr))->out_ports[match_level];
}

inline uint16_t
basic_binary_search_verify(Hash_Table_t ** hts, int i, char * query, int * lens, uint64_t * hash_values) {

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

    // NOTE that this hash lookup requires verifying strings if there is a FP match
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

  match_result[best_match]++;
  return ((Fwd_Info_Entry_t *)(best_addr))->out_ports[match_level];
}

int
basic_binary_search_test_worst(char * name_file, int line_count_input) {
  printf("Binary search of hash table, worst case test, file name = %s\n", name_file);

  char load_name_file[100];
  strcpy(load_name_file, name_file);
  char load_file_suffix[] = ".txt";
  strcat(load_name_file, load_file_suffix);
  printf("Load file = %s\n", load_name_file);

  Name_Entry_t * name_list;
  int line_count = load_prefixes_with_line_count(&name_list, load_name_file, line_count_input);
  int ht_size[MAX_COMP_NUM]; // hash_table_size

  int ii = 0;
  for (ii = 1; ii < MAX_COMP_NUM; ii++){
    match_result[ii] = 0;
    ht_size[ii] = line_count / 8;
  }

#ifdef Three_LEVEL
  // Create 7 hash tables
  // Populate only levels 4, 6, and 7
  int ht_min_size = 16;
  Hash_Table_t * hts[8];
  hts[1] = hash_table_init(ht_min_size, 0, 0);
  hts[2] = hash_table_init(ht_min_size, 1, 3);
  hts[3] = hash_table_init(ht_min_size, 0, 0);
  hts[4] = hash_table_init(2 * ht_size[4], 2, 6);
  hts[5] = hash_table_init(ht_min_size, 0, 0);
  hts[6] = hash_table_init(2 * ht_size[6], 5, 7);
  hts[7] = hash_table_init(2 * ht_size[7], 0, 0);
#endif

#ifdef Four_LEVEL
  //Create 15 hash tables
  // Populate only levels 8, 12, 14, 15
  int ht_min_size = 16;
  Hash_Table_t * hts[16];
  hts[1] = hash_table_init(ht_min_size, 0, 0);
  hts[2] = hash_table_init(ht_min_size, 1, 3);
  hts[3] = hash_table_init(ht_min_size, 0, 0);
  hts[4] = hash_table_init(ht_min_size, 2, 6);
  hts[5] = hash_table_init(ht_min_size, 0, 0);
  hts[6] = hash_table_init(ht_min_size, 5, 7);
  hts[7] = hash_table_init(ht_min_size, 0, 0);
  hts[8] = hash_table_init(2 * ht_size[8], 4, 12);
  hts[9] = hash_table_init(ht_min_size, 0, 0);
  hts[10] = hash_table_init(ht_min_size, 9, 11);
  hts[11] = hash_table_init(ht_min_size, 0, 0);
  hts[12] = hash_table_init(2 * ht_size[12], 10, 14);
  hts[13] = hash_table_init(ht_min_size, 0, 0);
  hts[14] = hash_table_init(2 * ht_size[14], 13, 15);
  hts[15] = hash_table_init(2 * ht_size[15], 0, 0);
#endif

  // Allocate memory for name prefix entries
#define MAX_BLOCK 8 // Set larger values for larger datasets
  int current_index = 0;
  void * base[MAX_BLOCK];
  void * block_end[MAX_BLOCK];
  void * next_free;
  void * mem_end;
  uint64_t size_hex = 1000000000; // 1GB
  size_t mem_size = (size_t)(size_hex);

  int p;
  for (p = 0; p < MAX_BLOCK; p++) {

#ifdef RTE_HUGEPAGE
    base[p] = rte_zmalloc(NULL, mem_size, CACHE_LINE);
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
  }

  current_index = 0;
  next_free = base[current_index];
  mem_end = block_end[current_index];

#ifdef Three_LEVEL
  int lookup_line_count = line_count / 3;
#endif

#ifdef Four_LEVEL
  int lookup_line_count = line_count / 4;
#endif

  int insertion_phase_1 = line_count - lookup_line_count;
  printf("insertion_phase_1 = %d\n", insertion_phase_1);
  fflush(stdout);

#if BST_PROF
  uint64_t bst_start = 0, bst_end = 0, bst_diff = 0;
  static uint64_t bst_count = 0;
  static uint64_t bst_total = 0;
  // static uint64_t bst_l3_read = 0;
  // static uint64_t bst_l3_miss = 0;
  // static uint64_t bst_tlb_dmiss = 0;
#endif

#if PREF_PROF
  uint64_t p_start, p_end;
  static uint64_t p_total = 0;
  static uint64_t p_count = 0;
#endif

  int i;

  // For SipHash
#ifdef SIPHASH
  for (i = 0; i < FWD_KEYLEN; i++) {
    k[i] = i;
  }

  uint64_t v0_s_t = 0x736f6d6570736575ULL;
  uint64_t v1_s_t = 0x646f72616e646f6dULL;
  uint64_t v2_s_t = 0x6c7967656e657261ULL;
  uint64_t v3_s_t = 0x7465646279746573ULL;
  uint64_t k0_s_t = U8TO64_LE( k );
  uint64_t k1_s_t = U8TO64_LE( k + 8 );
  v3_s_t ^= k1_s_t;
  v2_s_t ^= k0_s_t;
  v1_s_t ^= k1_s_t;
  v0_s_t ^= k0_s_t;

  const uint64_t v3_s = v3_s_t;
  const uint64_t v2_s = v2_s_t;
  const uint64_t v1_s = v1_s_t;
  const uint64_t v0_s = v0_s_t;
#endif

  int j;
  int lens[20];
  char * prefix;
  char * pch;
  uint8_t max_comp;
  uint64_t hash_value = 0;

#ifdef SIPHASH
  uint8_t * in;
  uint64_t len;
#endif

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  //     Insertion Phase ONE (do not store strings)
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  for (i = line_count - insertion_phase_1; i < line_count; i++) {

    max_comp = 1;
    prefix = name_list[i].name + NAME_OFFSET;

    pch=strchr(prefix,'/');
    while (pch!=NULL) {
      lens[max_comp] = pch-prefix+1;
      max_comp++;
      pch=strchr(pch+1,'/');

      if (max_comp >= MAX_COMP_NUM)
        break;
    } // while
    assert(max_comp <= MAX_COMP_NUM);

    for (j = 1; j < MAX_COMP_NUM; j++) {

#ifdef Three_LEVEL
      // Skip name component levels at 1, 2, 3, and 5
      if (j == 1 || j == 2 || j == 3 || j == 5) {
        continue;
      }
#endif

#ifdef Four_LEVEL
      // Skip the name component levels that will not be stored
      if (j <= 7 || j == 9 || j == 10 || j == 11 || j == 13) {
        continue;
      }
#endif

  #ifdef CITYHASH
      hash_value = CityHash64(prefix, lens[j]);
  #endif

  #ifdef SIPHASH
      in = (uint8_t *)prefix;
      uint64_t v0 = v0_s;
      uint64_t v1 = v1_s;
      uint64_t v2 = v2_s;
      uint64_t v3 = v3_s;

      len = lens[j];
      const uint8_t *end = (uint8_t *)prefix + len - ( len % sizeof( uint64_t ));
      siphash_step(&v0, &v1, &v2, &v3, &in, end, len, &hash_value);

  #endif
      hash_table_insert((Hash_Table_t *)hts[j], prefix, lens[j], hash_value, NULL);
      // NULL: strings are not stored
    }
  }


  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  //     Free sequential name list
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  free_prefixes(name_list, line_count);
  printf("Phase 1 name list freed.\n");

  char insert_name_file[100];
  strcpy(insert_name_file, name_file);
  char insert_file_suffix[] = ".prefix.txt";
  strcat(insert_name_file, insert_file_suffix);
  line_count = load_prefixes(&name_list, insert_name_file);
  printf("Phase 2, insertion file name = %s\n", insert_name_file);
  printf("Insertion file line_count = %d\n", line_count);

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

  #ifdef CITYHASH
      hash_value = CityHash64(prefix, lens[j]);
  #endif

  #ifdef SIPHASH
      in = (uint8_t *)prefix;
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

      hash_table_insert_verify((Hash_Table_t *)hts[j], prefix, lens[j], hash_value, next_free, level);
      total_str_mem += (1 + (lens[j] + FWD_INFO_SIZE) / 16) * 16;

      next_free = (void *)((uint64_t)next_free + (1 + (lens[j] + FWD_INFO_SIZE) / 16) * 16);
      if ( (uint64_t)next_free >= (uint64_t)mem_end) {
        ++current_index;
        // printf("current_index = %d\n", current_index);

      // Alternatively, name prefix entry memories can be allocated on-the-fly
/*
#ifdef RTE_HUGEPAGE
        base[current_index] = rte_malloc(NULL, mem_size, CACHE_LINE);
#else
        if (posix_memalign((void *)&(base[current_index]), CACHE_LINE, mem_size) != 0) {
          printf("posix_memalign string memory allocation failed\n");
          exit(1);
        }
        bzero(base[current_index], mem_size);
#endif
*/
        block_end[current_index] = (void *) ((uint64_t)base[current_index] + size_hex);
        next_free = base[current_index];
        mem_end = block_end[current_index];
      }

      assert((uint64_t)next_free % 16 == 0);

      if ((uint64_t)(next_free) >= (uint64_t)(mem_end)) {
        printf("Total string memory = %.2f GB\n", total_str_mem / 1024.0 / 1024.0 / 1024.0);
      }

      assert( (uint64_t)(next_free) < (uint64_t)(mem_end) );
    }
  }


  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  //     Free sequential name list
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  free_prefixes(name_list, line_count);

  char lookup_name_file[100];
  strcpy(lookup_name_file, name_file);
  char lookup_file_suffix[] = ".prefix.shuf";
  strcat(lookup_name_file, lookup_file_suffix);
  line_count = load_prefixes(&name_list, lookup_name_file);
  printf("Lookup file name = %s\n", lookup_name_file);
  printf("Lookup file line_count = %d\n", line_count);


  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  //     PRE-COMPUTE HASH VALUES
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

#ifdef PREHASH // pre compute hash values

  printf("Precalculate hash values\n");

  int max_lens_size = MAX_COMP_NUM;
  uint8_t * max_comp_array = (uint8_t *)calloc(line_count, sizeof(uint8_t));
  uint64_t * hash_values_array =
    (uint64_t *)calloc((uint64_t)MAX_COMP_NUM * (uint64_t)line_count, sizeof(uint64_t));
  int * lens_array = (int *)calloc((uint64_t)max_lens_size * (uint64_t)line_count, sizeof(int));

  // pre-compute hash values
  for (i = 0; i < line_count; i++) {

    uint64_t * hash_values = &hash_values_array[(uint64_t)i * (uint64_t)MAX_COMP_NUM];
    int * lens = &lens_array[(uint64_t)i * (uint64_t)max_lens_size];

    prefix = (char *)name_list[i].name + NAME_OFFSET;
    char * pch;
    max_comp = 1;
    pch=strchr(prefix,'/');
    while (pch!=NULL) {
      lens[max_comp] = pch-prefix+1;
      max_comp++;
      pch=strchr(pch+1,'/');
    }
    if (max_comp > MAX_COMP_NUM)
      max_comp = MAX_COMP_NUM;

    max_comp_array[i] = max_comp;

#ifdef SIPHASH
    in = (uint8_t *)prefix;
    uint64_t v0 = v0_s;
    uint64_t v1 = v1_s;
    uint64_t v2 = v2_s;
    uint64_t v3 = v3_s;
#endif

    j = 1;
    for (j = 1; j < max_comp; j++) {
#ifdef CITYHASH
      hash_values[j] = CityHash64(prefix, lens[j]);
#endif

#ifdef SIPHASH
      uint64_t len = lens[j];
      const uint8_t *end = (uint8_t *)prefix + len - ( len % sizeof(uint64_t));
      siphash_step(&v0, &v1, &v2, &v3, &in, end, len, &hash_values[j]);
#endif
    }
  }
#endif

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  //     LOOKUP
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  printf("---- Name prefix lookup begin ---\n");

  uint64_t hash_count = 0;
  uint64_t hash_values[MAX_COMP_NUM];
  int run;
  int run_count = g_run_count;
  printf("Number of experiments =\t%d\n", run_count);

  uint64_t start, end, diff;

#if HASH_CAL_PROF
  uint64_t h_start, h_end, hdiff = 0;
#endif

#if COMP_PROF
  uint64_t c_start = 0, c_end = 0, c_diff = 0;
  static uint64_t c_total = 0;
  static uint64_t c_count = 0;
#endif

#if PAPI_PROF

  int EventSet = PAPI_NULL;
  long long values1[3], values2[3];

  if (PAPI_library_init(PAPI_VER_CURRENT) != PAPI_VER_CURRENT)
    handle_error(0);

  if (PAPI_create_eventset(&EventSet) != PAPI_OK)
    handle_error(1);

  if (PAPI_add_event(EventSet, PAPI_L3_TCR) != PAPI_OK)
    handle_error(2);

  if (PAPI_add_event(EventSet, PAPI_L3_TCM) != PAPI_OK)
    handle_error(3);

  if (PAPI_add_event(EventSet, PAPI_TLB_DM) != PAPI_OK)
    handle_error(4);

  if (PAPI_start(EventSet) != PAPI_OK)
    handle_error(5);

  /* Read counters before workload running*/
  if (PAPI_read(EventSet, values1) != PAPI_OK)
    handle_error(6);

#endif

  start = rdtsc();
  for (run = 0; run < run_count; run++) {
    for (i = 0; i < lookup_line_count; i++) {

    prefix = (char *)name_list[i].name + NAME_OFFSET;
    // printf("prefix = %s\n", (char *)name_list[i].name);

#ifndef PREHASH // If NOT PREHASH

#if COMP_PROF
    c_start = rdtsc();
#endif

    char * pch;
    max_comp = 1;
    pch=strchr(prefix,'/');
    while (pch!=NULL) {
      lens[max_comp] = pch-prefix+1;
      max_comp++;
      pch=strchr(pch+1,'/');
    }

  if (max_comp > MAX_COMP_NUM)
    max_comp = MAX_COMP_NUM;

#if ENABLE_PREFETCH_NONE
#if BST_PROF
      bst_start = rdtsc();
#endif

#ifdef ALWAYS_MATCHING_VERIFY
      basic_binary_search_verify(hts, FIRST_HT, prefix, lens, hash_values);
#else
      basic_binary_search(hts, FIRST_HT, prefix, lens, hash_values);
#endif

#if BST_PROF
      bst_end = rdtsc();
      bst_diff = bst_end - bst_start;
      bst_count++;
      bst_total += bst_diff;
#endif

      continue; // skip the following lookup code

#endif // ENABLE_PREFETCH_NONE


#if HASH_CAL_PROF
          h_start = rdtsc();
#endif

#ifdef SIPHASH
    in = (uint8_t *)prefix;
    uint64_t v0 = v0_s;
    uint64_t v1 = v1_s;
    uint64_t v2 = v2_s;
    uint64_t v3 = v3_s;
#endif

#else
    // If hash values are precalculated.
    uint64_t hash_base = (uint64_t)(i) * (uint64_t)MAX_COMP_NUM;
    uint64_t len_base = (uint64_t)(i) * (uint64_t)(max_lens_size);
    max_comp = max_comp_array[i];
#endif // PREHASH

    j = 1;
    for (j = 1; j < max_comp; j++) {
#ifdef PREHASH
      hash_values[j] = hash_values_array[hash_base + j];
      lens[j] = lens_array[len_base + j];
#else

#ifdef CITYHASH
      hash_values[j] = CityHash64(prefix, lens[j]);
#endif

#ifdef SIPHASH
      uint64_t len = lens[j];
      uint8_t *end = (uint8_t *)prefix + len - ( len % sizeof(uint64_t));
      siphash_step(&v0, &v1, &v2, &v3, &in, end, len, &hash_values[j]);
#endif // SIPHASH

#endif // PREHASH

#if ENABLE_PREFETCH_ALL

#if PREF_PROF
   p_start = rdtsc();
#endif
  int32_t loc = (hash_values[j] >> 32) % hts[j]->size;

  uint32_t offset = loc & 0xffffff;
  uint32_t block_index = loc >> 24;
  prefetch((void *) &(hts[j]->buckets[block_index][offset]));

#if PREF_PROF
   p_end = rdtsc();
   p_total += (p_end - p_start);
   p_count++;
#endif

#endif
// END IF ENABLE_PREFETCH_ALL

#if ENABLE_PREFETCH_FIRST
        if (unlikely(j == FIRST_HT)){
          uint32_t loc = (hash_values[FIRST_HT] >> 32) % hts[FIRST_HT]->size;
          uint32_t offset = loc & 0xffffff;
          uint32_t block_index = loc >> 24;
          prefetch((void *) &(hts[FIRST_HT]->buckets[block_index][offset]));
        }
#endif

    }

#if HASH_CAL_PROF
          h_end = rdtsc();
          hdiff += h_end - h_start;
          hash_count += max_comp-1;
#endif

#if COMP_PROF
  c_end = rdtsc();
  c_diff = c_end - c_start;
  c_total += c_diff;
  c_count++;
#endif

// ================ Binary Search ==================================

#if BST_PROF
      bst_start = rdtsc();
#endif

#ifdef ALWAYS_MATCHING_VERIFY
      basic_binary_search_verify(hts, FIRST_HT, prefix, lens, hash_values);
#else
      basic_binary_search(hts, FIRST_HT, prefix, lens, hash_values);
#endif

#if BST_PROF
      bst_end = rdtsc();
      bst_diff = bst_end - bst_start;
      bst_count++;
      bst_total += bst_diff;
#endif

    }
  }
  end = rdtsc();
  diff = end - start;

#if PAPI_PROF
  /* Read counters after workload running*/
  if (PAPI_read(EventSet, values2) != PAPI_OK)
    handle_error(1);

  uint64_t bst_l3_miss = (uint64_t)(values2[0] - values1[0]);
  uint64_t bst_l3_read = (uint64_t)(values2[1] - values1[1]);
  uint64_t bst_tlb_dmiss = (uint64_t)(values2[2] - values1[2]);

#endif

  printf("\n-----------------------------------------\n");
  printf("File name = %s\n", name_file);

#if ENABLE_PREFETCH_ALL
  printf("* Prefetch ALL\n");
#endif

#if ENABLE_PREFETCH_FIRST
  printf("* Prefetch First\n");
#endif

#ifdef SIPHASH
  printf("SIPHASH\n");
#endif

#ifdef CITYHASH
  printf("CITYHASH\n");
#endif

#ifdef ALWAYS_MATCHING_VERIFY
  printf("Perform string matching at ALL levels.\n");
#endif

#ifdef VERIFY_MATCHING
  printf("Perform string matching only in the END.\n");
#endif
  printf("\n--- Overall Performance---\n");
  printf("Tot cycles %" PRIu64"\n", diff);
  printf("Avg cycles %f\n", (double)diff/(double)(lookup_line_count * run_count));

#if HASH_CAL_PROF
  printf("\n--- HASH PROF ---\n");
  printf("hash count = %" PRIu64"\n", hash_count);
  printf("Avg hash compute cycles %f\n", (double)hdiff / (double)hash_count);
#endif

#if G_HASH_CAL_PROF
  printf("\n--- Global HASH PROF ---\n");
  printf("hash count = %" PRIu64"\n", g_h_total_count);
  printf("Avg hash compute cycles %f\n", (double)g_h_total / (double)g_h_total_count);
#endif

#if BST_PROF
  printf("\n--- BST PROF ---\n");
  printf("Total binary search count = %" PRIu64"\n", bst_count);
  printf("Total binary search cycles = %" PRIu64"\n", bst_total);
  printf("Avg binary search = %f cycles\n", (double)bst_total / (double)bst_count);
#endif

#if PAPI_PROF
  printf("Total binary search l3 miss = %" PRIu64"\n", bst_l3_miss);
  printf("Total binary search l3 read = %" PRIu64"\n", bst_l3_read);
  printf("Total binary search tlb dmiss = %" PRIu64"\n", bst_tlb_dmiss);
#endif

#if COMP_PROF
  printf("\n--- COMP PROF ---\n");
  printf("Total computation cost = %" PRIu64" cycles\n", c_total);
  printf("Total computation count = %" PRIu64" times\n", c_count);
  printf("Average computation cost = %f cycles\n", (double)c_total / (double)c_count);
#endif

#if PREF_PROF
  printf("\n--- PREFETCH PROF ---\n");
  printf("Total prefetch cost = %" PRIu64" cycles\n", p_total);
  printf("Total prefetch count = %" PRIu64" times\n", p_count);
  printf("Average prefetch cost = %f cycles\n", (double)p_total / (double)p_count);
#endif

  for (i = 1; i < MAX_COMP_NUM; i++) {
    printf("Best match result [%d] = %" PRIu64"\n", i, match_result[i]);
  }

#ifdef VERIFY_MATCHING
  printf("detected false positives = %" PRIu64 "\n", basic_bst_false_positive);
#endif
  printf("Total string memory = %.2f GB\n", total_str_mem / 1024.0 / 1024.0 / 1024.0);

  // Memory release
  for (i = 1; i < MAX_COMP_NUM; i++) {
    hash_table_destroy(hts[i]);
  }

  for (i = 0; i < MAX_BLOCK; i++) {
    if (base[i]) {
#ifdef RTE_HUGEPAGE
      rte_free(base[i]);
#else
      free(base[i]);
#endif
    }
  }

  return 0;
}
