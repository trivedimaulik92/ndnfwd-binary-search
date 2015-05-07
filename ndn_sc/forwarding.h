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

#ifndef FORWARDING_H
#define FORWARDING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <inttypes.h>

#include "debug.h"
#include "city.h"
#include "utils.h"
#include "hash_table.h"
#include "siphash24.h"

// Configure the forwarding engine to work with datasets with seven name components & 15 name components
#define Three_LEVEL  // 7 name components
// #define Four_LEVEL      // 15 name components

// Used for pre-allocating memory for the traces
typedef struct Name_Entry{
#ifdef Three_LEVEL
  char name[100];
#endif

#ifdef Four_LEVEL
  char name[200];
#endif

} Name_Entry_t;

// #define NAME_OFFSET_1
// #define NAME_OFFSET_2
#define NAME_OFFSET_3

#define ENABLE_PREFETCH_NONE 0 // Enable this to perform hash computation only right before the hash bucket access
#define ENABLE_PREFETCH_ALL 0 // prefetch all k hash table buckets
#define ENABLE_PREFETCH_FIRST 0 // prefetch only the first hash table

#define PAPI_PROF 0
#define COMP_PROF 0 // profiling cycles spent on non-memory access activities
#define G_HASH_CAL_PROF 0 // profiling hash calculation
#define HASH_CAL_PROF 0 // profiling hash calculation
#define BST_PROF 0 // profiling binary search of hash tables
#define PREF_PROF 0 // profiling prefetch instruction

//#define PREHASH // pre-calculate hash values
#define RTE_HUGEPAGE // using large pages

// #define SIPHASH
// #define VERIFY_MATCHING // Verify matching in the end
#define CITYHASH
#define ALWAYS_MATCHING_VERIFY // Performs matching once there is a fingerprint match

#define prefetch(addr) __builtin_prefetch(addr);
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#ifdef NAME_OFFSET_1
#define NAME_OFFSET 2
#endif

#ifdef NAME_OFFSET_2
#define NAME_OFFSET 3
#endif

#ifdef NAME_OFFSET_3
#define NAME_OFFSET 4
#endif

#ifdef Three_LEVEL
#define FIRST_HT 4
#define MAX_COMP_NUM 8
#endif

#ifdef Four_LEVEL
#define FIRST_HT 8
#define MAX_COMP_NUM 16
#endif

// read name prefixes from file to a name entry array
int
load_prefixes(Name_Entry_t ** name_list_p, char * file_name);

// read name prefixes from file to a name entry array given the number of prefixes in the file
int
load_prefixes_with_line_count(Name_Entry_t ** name_list_p, char * file_name, int line_count);

// free the memory allocated for the name entry array
int
free_prefixes(Name_Entry_t * name_list, int line_count);

// binary search of hash tables that performs string verification only in the end
inline uint16_t
basic_binary_search(Hash_Table_t ** hts, int i, char * query, int * lens, uint64_t * hash_values);

// binary search of hash tables that performs string verification whenever there is a fingerprint match
inline uint16_t
basic_binary_search_verify(Hash_Table_t ** hts, int i, char * query, int * lens, uint64_t * hash_values);

// testing the worst-case performance of binary search of hash tables
int
basic_binary_search_test_worst(char * name_file, int line_count);

#if PAPI_PROF
void handle_error (int retval);
#endif

#endif
