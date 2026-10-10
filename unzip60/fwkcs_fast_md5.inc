/*
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#define IZ_MD5_ROL(x, r) (((x) << (r)) | ((x) >> (32 - (r))))

unsigned int a = state[0], b = state[1], c = state[2], d = state[3], x[16];
unsigned i;

for (i = 0; i < 16; i++)
  {
    x[i] = (unsigned int)block[i * 4] | ((unsigned int)block[i * 4 + 1] << 8)
           | ((unsigned int)block[i * 4 + 2] << 16)
           | ((unsigned int)block[i * 4 + 3] << 24);
  }

a = b + IZ_MD5_ROL (a + ((b & c) | ((~b) & d)) + 0xd76aa478U + x[0], 7);
d = a + IZ_MD5_ROL (d + ((a & b) | ((~a) & c)) + 0xe8c7b756U + x[1], 12);
c = d + IZ_MD5_ROL (c + ((d & a) | ((~d) & b)) + 0x242070dbU + x[2], 17);
b = c + IZ_MD5_ROL (b + ((c & d) | ((~c) & a)) + 0xc1bdceeeU + x[3], 22);
a = b + IZ_MD5_ROL (a + ((b & c) | ((~b) & d)) + 0xf57c0fafU + x[4], 7);
d = a + IZ_MD5_ROL (d + ((a & b) | ((~a) & c)) + 0x4787c62aU + x[5], 12);
c = d + IZ_MD5_ROL (c + ((d & a) | ((~d) & b)) + 0xa8304613U + x[6], 17);
b = c + IZ_MD5_ROL (b + ((c & d) | ((~c) & a)) + 0xfd469501U + x[7], 22);
a = b + IZ_MD5_ROL (a + ((b & c) | ((~b) & d)) + 0x698098d8U + x[8], 7);
d = a + IZ_MD5_ROL (d + ((a & b) | ((~a) & c)) + 0x8b44f7afU + x[9], 12);
c = d + IZ_MD5_ROL (c + ((d & a) | ((~d) & b)) + 0xffff5bb1U + x[10], 17);
b = c + IZ_MD5_ROL (b + ((c & d) | ((~c) & a)) + 0x895cd7beU + x[11], 22);
a = b + IZ_MD5_ROL (a + ((b & c) | ((~b) & d)) + 0x6b901122U + x[12], 7);
d = a + IZ_MD5_ROL (d + ((a & b) | ((~a) & c)) + 0xfd987193U + x[13], 12);
c = d + IZ_MD5_ROL (c + ((d & a) | ((~d) & b)) + 0xa679438eU + x[14], 17);
b = c + IZ_MD5_ROL (b + ((c & d) | ((~c) & a)) + 0x49b40821U + x[15], 22);
a = b + IZ_MD5_ROL (a + ((d & b) | ((~d) & c)) + 0xf61e2562U + x[1], 5);
d = a + IZ_MD5_ROL (d + ((c & a) | ((~c) & b)) + 0xc040b340U + x[6], 9);
c = d + IZ_MD5_ROL (c + ((b & d) | ((~b) & a)) + 0x265e5a51U + x[11], 14);
b = c + IZ_MD5_ROL (b + ((a & c) | ((~a) & d)) + 0xe9b6c7aaU + x[0], 20);
a = b + IZ_MD5_ROL (a + ((d & b) | ((~d) & c)) + 0xd62f105dU + x[5], 5);
d = a + IZ_MD5_ROL (d + ((c & a) | ((~c) & b)) + 0x02441453U + x[10], 9);
c = d + IZ_MD5_ROL (c + ((b & d) | ((~b) & a)) + 0xd8a1e681U + x[15], 14);
b = c + IZ_MD5_ROL (b + ((a & c) | ((~a) & d)) + 0xe7d3fbc8U + x[4], 20);
a = b + IZ_MD5_ROL (a + ((d & b) | ((~d) & c)) + 0x21e1cde6U + x[9], 5);
d = a + IZ_MD5_ROL (d + ((c & a) | ((~c) & b)) + 0xc33707d6U + x[14], 9);
c = d + IZ_MD5_ROL (c + ((b & d) | ((~b) & a)) + 0xf4d50d87U + x[3], 14);
b = c + IZ_MD5_ROL (b + ((a & c) | ((~a) & d)) + 0x455a14edU + x[8], 20);
a = b + IZ_MD5_ROL (a + ((d & b) | ((~d) & c)) + 0xa9e3e905U + x[13], 5);
d = a + IZ_MD5_ROL (d + ((c & a) | ((~c) & b)) + 0xfcefa3f8U + x[2], 9);
c = d + IZ_MD5_ROL (c + ((b & d) | ((~b) & a)) + 0x676f02d9U + x[7], 14);
b = c + IZ_MD5_ROL (b + ((a & c) | ((~a) & d)) + 0x8d2a4c8aU + x[12], 20);

a = b + IZ_MD5_ROL (a + (b ^ c ^ d) + 0xfffa3942U + x[5], 4);
d = a + IZ_MD5_ROL (d + (a ^ b ^ c) + 0x8771f681U + x[8], 11);
c = d + IZ_MD5_ROL (c + (d ^ a ^ b) + 0x6d9d6122U + x[11], 16);
b = c + IZ_MD5_ROL (b + (c ^ d ^ a) + 0xfde5380cU + x[14], 23);
a = b + IZ_MD5_ROL (a + (b ^ c ^ d) + 0xa4beea44U + x[1], 4);
d = a + IZ_MD5_ROL (d + (a ^ b ^ c) + 0x4bdecfa9U + x[4], 11);
c = d + IZ_MD5_ROL (c + (d ^ a ^ b) + 0xf6bb4b60U + x[7], 16);
b = c + IZ_MD5_ROL (b + (c ^ d ^ a) + 0xbebfbc70U + x[10], 23);
a = b + IZ_MD5_ROL (a + (b ^ c ^ d) + 0x289b7ec6U + x[13], 4);
d = a + IZ_MD5_ROL (d + (a ^ b ^ c) + 0xeaa127faU + x[0], 11);
c = d + IZ_MD5_ROL (c + (d ^ a ^ b) + 0xd4ef3085U + x[3], 16);
b = c + IZ_MD5_ROL (b + (c ^ d ^ a) + 0x04881d05U + x[6], 23);
a = b + IZ_MD5_ROL (a + (b ^ c ^ d) + 0xd9d4d039U + x[9], 4);
d = a + IZ_MD5_ROL (d + (a ^ b ^ c) + 0xe6db99e5U + x[12], 11);
c = d + IZ_MD5_ROL (c + (d ^ a ^ b) + 0x1fa27cf8U + x[15], 16);
b = c + IZ_MD5_ROL (b + (c ^ d ^ a) + 0xc4ac5665U + x[2], 23);

a = b + IZ_MD5_ROL (a + (c ^ (b | (~d))) + 0xf4292244U + x[0], 6);
d = a + IZ_MD5_ROL (d + (b ^ (a | (~c))) + 0x432aff97U + x[7], 10);
c = d + IZ_MD5_ROL (c + (a ^ (d | (~b))) + 0xab9423a7U + x[14], 15);
b = c + IZ_MD5_ROL (b + (d ^ (c | (~a))) + 0xfc93a039U + x[5], 21);
a = b + IZ_MD5_ROL (a + (c ^ (b | (~d))) + 0x655b59c3U + x[12], 6);
d = a + IZ_MD5_ROL (d + (b ^ (a | (~c))) + 0x8f0ccc92U + x[3], 10);
c = d + IZ_MD5_ROL (c + (a ^ (d | (~b))) + 0xffeff47dU + x[10], 15);
b = c + IZ_MD5_ROL (b + (d ^ (c | (~a))) + 0x85845dd1U + x[1], 21);
a = b + IZ_MD5_ROL (a + (c ^ (b | (~d))) + 0x6fa87e4fU + x[8], 6);
d = a + IZ_MD5_ROL (d + (b ^ (a | (~c))) + 0xfe2ce6e0U + x[15], 10);
c = d + IZ_MD5_ROL (c + (a ^ (d | (~b))) + 0xa3014314U + x[6], 15);
b = c + IZ_MD5_ROL (b + (d ^ (c | (~a))) + 0x4e0811a1U + x[13], 21);
a = b + IZ_MD5_ROL (a + (c ^ (b | (~d))) + 0xf7537e82U + x[4], 6);
d = a + IZ_MD5_ROL (d + (b ^ (a | (~c))) + 0xbd3af235U + x[11], 10);
c = d + IZ_MD5_ROL (c + (a ^ (d | (~b))) + 0x2ad7d2bbU + x[2], 15);
b = c + IZ_MD5_ROL (b + (d ^ (c | (~a))) + 0xeb86d391U + x[9], 21);

state[0] = (z_uint4)((unsigned int)state[0] + a);
state[1] = (z_uint4)((unsigned int)state[1] + b);
state[2] = (z_uint4)((unsigned int)state[2] + c);
state[3] = (z_uint4)((unsigned int)state[3] + d);

#undef IZ_MD5_ROL
