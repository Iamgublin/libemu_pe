//  boost cstdint.hpp header file  ------------------------------------------//

//  (C) Copyright Beman Dawes 1999. 
//  (C) Copyright Jens Mauer 2001  
//  (C) Copyright John Maddock 2001 
//  Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

//  See http://www.boost.org/libs/integer for documentation.

//  Revision History
//   31 Oct 01  use BOOST_HAS_LONG_LONG to check for "long long" (Jens M.)
//   16 Apr 01  check LONGLONG_MAX when looking for "long long" (Jens Maurer)
//   23 Jan 01  prefer "long" over "int" for int32_t and intmax_t (Jens Maurer)
//   12 Nov 00  Merged <boost/stdint.h> (Jens Maurer)
//   23 Sep 00  Added INTXX_C macro support (John Maddock).
//   22 Sep 00  Better 64-bit support (John Maddock)
//   29 Jun 00  Reimplement to avoid including stdint.h within namespace boost
//    8 Aug 99  Initial version (Beman Dawes)

#ifndef HAVE_INTTYPES_H
#define HAVE_INTTYPES_H

typedef long            int32_t;
typedef long            int_least32_t;
typedef long            int_fast32_t;
typedef unsigned long   uint32_t;
typedef unsigned long   uint_least32_t;
typedef unsigned long   uint_fast32_t;

typedef unsigned char   uint8_t;
typedef char            int8_t;
typedef unsigned short  uint16_t;
typedef short			int16_t;

typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;

#define EOPNOTSUPP 45 

#endif 