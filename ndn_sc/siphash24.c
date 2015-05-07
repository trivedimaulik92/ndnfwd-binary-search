/*
 *  Copyright (c) 2014-2015 Washington University in St. Louis.
 *  Comments: added the siphash_step() function
 *
 */

/*
   SipHash reference C implementation

   Copyright (c) 2012-2014 Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
   Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "siphash24.h"
#include <inttypes.h>

inline uint64_t siphash(const uint8_t *in, uint64_t inlen, const uint8_t *k )
{
  /* "somepseudorandomlygeneratedbytes" */
  uint64_t v0 = 0x736f6d6570736575ULL;
  uint64_t v1 = 0x646f72616e646f6dULL;
  uint64_t v2 = 0x6c7967656e657261ULL;
  uint64_t v3 = 0x7465646279746573ULL;
  uint64_t b;
  uint64_t k0 = U8TO64_LE( k );
  uint64_t k1 = U8TO64_LE( k + 8 );
  uint64_t m;
  int i;
  const uint8_t *end = in + inlen - ( inlen % sizeof( uint64_t ) );
  const int left = inlen & 7;
  b = ( ( uint64_t )inlen ) << 56;
  v3 ^= k1;
  v2 ^= k0;
  v1 ^= k1;
  v0 ^= k0;

#ifdef DOUBLE
  v1 ^= 0xee;
#endif


  for ( ; in != end; in += 8 )
  {
    m = U8TO64_LE( in );
    v3 ^= m;

    TRACE;
    for( i=0; i<cROUNDS; ++i ) SIPROUND;

    v0 ^= m;
  }

  // printf("org v0 = %" PRIu64 "\n", v0);
  // printf("org v1 = %" PRIu64 "\n", v1);
  // printf("org v2 = %" PRIu64 "\n", v2);
  // printf("org v3 = %" PRIu64 "\n", v3);
  // printf("org left = %d\n", left);
  // printf("org i = %d\n", i);

  switch( left )
  {
  case 7: b |= ( ( uint64_t )in[ 6] )  << 48;
  case 6: b |= ( ( uint64_t )in[ 5] )  << 40;
  case 5: b |= ( ( uint64_t )in[ 4] )  << 32;
  case 4: b |= ( ( uint64_t )in[ 3] )  << 24;
  case 3: b |= ( ( uint64_t )in[ 2] )  << 16;
  case 2: b |= ( ( uint64_t )in[ 1] )  <<  8;
  case 1: b |= ( ( uint64_t )in[ 0] ); break;
  case 0: break;
  }


  v3 ^= b;

  TRACE;
  for( i=0; i<cROUNDS; ++i ) SIPROUND;

  v0 ^= b;

#ifndef DOUBLE
  v2 ^= 0xff;
#else
  v2 ^= 0xee;
#endif

  TRACE;
  for( i=0; i<dROUNDS; ++i ) SIPROUND;

  b = v0 ^ v1 ^ v2  ^ v3;
  // U64TO8_LE( out, b );

#ifdef DOUBLE
  v1 ^= 0xdd;

  TRACE;
  for( i=0; i<dROUNDS; ++i ) SIPROUND;

  b = v0 ^ v1 ^ v2  ^ v3;
  // U64TO8_LE( out+8, b );
#endif

  return b;
}

inline void
siphash_step(uint64_t * v0_in_p, uint64_t * v1_in_p, uint64_t * v2_in_p, uint64_t * v3_in_p,
                  uint8_t ** in_p, const uint8_t * end, uint64_t inlen, uint64_t * hash_value)
{
  uint64_t v0 = *v0_in_p;
  uint64_t v1 = *v1_in_p;
  uint64_t v2 = *v2_in_p;
  uint64_t v3 = *v3_in_p;
  uint8_t * in = *in_p;


  uint64_t m;
  const int left = inlen & 7;
  uint64_t b = ( ( uint64_t )inlen ) << 56; // make ure inlen is from the beginning

  int i;
  for ( ; in != end; in += 8 ) // This input is the modified input
  {
    m = U8TO64_LE( in );
    v3 ^= m;

    TRACE;
    for( i=0; i<cROUNDS; ++i ) SIPROUND;

    v0 ^= m;
  }


  for ( ; in != end; in += 8 )
  {
    m = U8TO64_LE( in );
    v3 ^= m;

    TRACE;
    for( i=0; i<cROUNDS; ++i ) SIPROUND;

    v0 ^= m;
  }

  // record all the changes before finalize the results
  *v0_in_p = v0;
  *v1_in_p = v1;
  *v2_in_p = v2;
  *v3_in_p = v3;
  *in_p = in;

  switch( left )
  {
  case 7: b |= ( ( uint64_t )in[ 6] )  << 48;
  case 6: b |= ( ( uint64_t )in[ 5] )  << 40;
  case 5: b |= ( ( uint64_t )in[ 4] )  << 32;
  case 4: b |= ( ( uint64_t )in[ 3] )  << 24;
  case 3: b |= ( ( uint64_t )in[ 2] )  << 16;
  case 2: b |= ( ( uint64_t )in[ 1] )  <<  8;
  case 1: b |= ( ( uint64_t )in[ 0] ); break;
  case 0: break;
  }

  v3 ^= b;

  TRACE;
  for( i=0; i<cROUNDS; ++i ) SIPROUND;

  v0 ^= b;

#ifndef DOUBLE
  v2 ^= 0xff;
#else
  v2 ^= 0xee;
#endif

  TRACE;
  for( i=0; i<dROUNDS; ++i ) SIPROUND;

  b = v0 ^ v1 ^ v2  ^ v3;
  // U64TO8_LE( out, b );

#ifdef DOUBLE
  v1 ^= 0xdd;

  TRACE;
  for( i=0; i<dROUNDS; ++i ) SIPROUND;

  b = v0 ^ v1 ^ v2  ^ v3;
  // U64TO8_LE( out+8, b );
#endif

  *hash_value = b;
}
