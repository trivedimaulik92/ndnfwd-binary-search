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
#include "utils.h"
#include "hash_table.h"

#define Three_LEVEL
// #define Four_LEVEL

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

// #define DUAL_SOCKETS // duplicate data structures in NUMA nodes

#define ENABLE_PREFETCH_NONE 0 // Enable this to perform hash computation only right before the hash bucket access
#define ENABLE_PREFETCH_ALL 0 // prefetch all hash table buckets right after finishing the hash calculation
#define ENABLE_PREFETCH_FIRST 0


#define PAPI_PROF 0
#define COMP_PROF 0 // profiling cycles spent on non-memory access activities
#define G_HASH_CAL_PROF 0 // profiling hash calculation
#define HASH_CAL_PROF 0 // profiling hash calculation
#define BST_PROF 0 // profiling binary search of hash tables
#define PREF_PROF 0 // profiling prefetch instruction

// #define PREHASH // pre-calculate hash values
#define RTE_HUGEPAGE

#define SIPHASH
#define VERIFY_MATCHING
// #define CITYHASH
// #define ALWASY_MATCHING_VERIFY

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

#define prefetch(addr) __builtin_prefetch(addr);

int
load_prefixes(Name_Entry_t ** name_list_p, char * file_name);

int
load_prefixes_with_line_count(Name_Entry_t ** name_list_p, char * file_name, int line_count);

int
load_prefixes_socket(Name_Entry_t ** name_list_p, char * file_name, int socket);

int
free_prefixes(Name_Entry_t * name_list, int line_count);

inline uint16_t
basic_binary_search(Hash_Table_t ** hts, int i, char * query, int * lens, uint64_t * hash_values);

inline uint16_t
basic_binary_search_verify(Hash_Table_t ** hts, int i, char * query, int * lens, uint64_t * hash_values);

// For 7 name components or 15 name components
int
basic_binary_search_test_worst(char * name_file, int line_count_input);


#if PAPI_PROF
void handle_error (int retval);
#endif
#endif
