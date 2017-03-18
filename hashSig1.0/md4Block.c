/*

This version of the algorithm has been modified by Ralph C. Merkle
90.03.12.  Basically, various portions of the general-purpose hash
provided by Ron Rivest and RSA Data Security have been removed,
leaving only the guts of the algorithm for use as a simple "block
hash" algorithm.

The following notice came from the version posted to sci.crypt
by RSA Data Security:

License to copy and use this document and the software described
herein is granted provided it is identified as the "RSA Data
Security, Inc. MD4 Message Digest Algorithm" in all materials
mentioning or referencing this software, function, or document.
 
License is also granted to make derivative works provided that such
works are identified as "derived from the RSA Data Security, Inc. MD4
Message Digest Algorithm" in all material mentioning or referencing
the derived work.
 
RSA Data Security, Inc. makes no representations concerning the
merchantability of this algorithm or software or their suitability
for any specific purpose.  It is provided "as is" without express or
implied warranty of any kind.
 
These notices must be retained in any copies of any part of this
documentation and/or software.
------------------------------------------------------------------
 * XEROX GRANTS NO DIFFERENT OR ADDITIONAL RIGHTS TO USE THE
 * MODIFIED VERSION OF MD4 CONTAINED HEREIN.

*/

/*  The original comments, documentation, and explanations have
    been retained, but they no longer are fully applicable to the
    "stripped" version of md4 actually coded here.
*/

#if 0

------------------------------------------------------------------------
------------------------------------------------------------------------

		 The MD4 Message Digest Algorithm
		 --------------------------------
			by Ronald L. Rivest
	MIT Laboratory for Computer Science, Cambridge, Mass. 02139
				and
	RSA Data Security, Inc., Redwood City, California 94065
		    (Version 2/17/90 -- Revised)


Abstract:
---------
			    
This note describes the MD4 message digest algorithm.  The algorithm
takes as input an input message of arbitrary length and produces as
output a 128-bit ``fingerprint'' or ``message digest'' of the input.
It is conjectured that it is computationally infeasible to produce two
messages having the same message digest, or to produce any message
having a given prespecified target message digest.  The MD4 algorithm
is thus ideal for digital signature applications, where a large file
must be ``compressed'' in a secure manner before being signed with the
RSA public-key cryptosystem.

The MD4 algorithm is designed to be quite fast on 32-bit machines.  On
a SUN Sparc station, MD4 runs at 1,450,000 bytes/second.  On a DEC
MicroVax II, MD4 runs at approximately 70,000 bytes/second.  On a 20MHz
80286, MD4 runs at approximately 32,000 bytes/second.  In addition, the
MD4 algorithm does not require any large substitution tables; the
algorithm can be coded quite compactly.

The MD4 algorithm is being placed in the public domain for review and
possible adoption as a standard.  

(Note: The document supersedes an earlier draft.  The algorithm described
       here is a slight modification of the one described in the draft.)


I. Terminology and Notation
---------------------------

In this note a ``word'' is a 32-bit quantity and a byte is an 8-byte
quantity.  A sequence of bits can be interpreted in a natural manner
as a sequence of bytes, where each consecutive group of 8 bits is
interpreted as a byte with the high-order (most significant) bit of
each byte listed first.  Similarly, a sequence of bytes can be
interpreted as a sequence of 32-bit words, where each consecutive
group of 4 bytes is interpreted as a word with the low-order (least
significant) byte given first.

Let x_i denote ``x sub i''.  If the subscript is an expression, we
surround it in braces, as in x_{i+1}.  Similarly, we use ^ for
superscripts (exponentiation), so that x^i denotes x to the i-th
power.

Let the symbol ``+'' denote addition of words (i.e., modulo-2^32
addition). Let X <<< s denote the 32-bit value obtained by circularly
shifting (rotating) X left by s bit positions.  Let not(X) denote the
bit-wise complement of X, and let X v Y denote the bit-wise OR of X
and Y.  Let X xor Y denote the bit-wise XOR of X and Y, and let XY
denote the bit-wise AND of X and Y.


II. MD4 Algorithm Description
-----------------------------

We begin by supposing that we have a b-bit message as input, and
that we wish to find its message digest.  Here b is an arbitrary
nonnegative integer; b may be zero, it need not be a multiple of 8,
and it may be arbitrarily large. We imagine the bits of the message
written down as follows:

	m_0 m_1 ... m_{b-1} .

The following five steps are performed to compute the message digest of the
message.


Step 1. Append padding bits
---------------------------

The message is ``padded'' (extended) so that its length (in bits) is
congruent to 448, modulo 512.  That is, the message is extended so
that it is just 64 bits shy of being a multiple of 512 bits long.
Padding is always performed, even if the length of the message is
already congruent to 448, modulo 512 (in which case 512 bits of
padding are added).

Padding is performed as follows: a single ``1'' bit is appended to the
message, and then enough zero bits are appended so that the length in bits
of the padded message becomes congruent to 448, modulo 512.


Step 2. Append length
---------------------

A 64-bit representation of b (the length of the message before the
padding bits were added) is appended to the result of the previous
step.  In the unlikely event that b is greater than 2^64, then only
the low-order 64 bits of b are used.  (These bits are appended as two
32-bit words and appended low-order word first in accordance with the
previous conventions.)

At this point the resulting message (after padding with bits and with
b) has a length that is an exact multiple of 512 bits.  Equivalently,
this message has a length that is an exact multiple of 16 (32-bit)
words.  Let M[0 ... N-1] denote the words of the resulting message,
where N is a multiple of 16.


Step 3. Initialize MD buffer
----------------------------

A 4-word buffer (A,B,C,D) is used to compute the message digest.  Here
each of A,B,C,D are 32-bit registers.  These registers are initialized
to the following values (in hexadecimal, low-order bytes first):

	word A:    01 23 45 67
	word B:    89 ab cd ef
	word C:    fe dc ba 98
	word D:    76 54 32 10


Step 4. Process message in 16-word blocks
-----------------------------------------

We first define three auxiliary functions that each take as input
three 32-bit words and produce as output one 32-bit word.

	f(X,Y,Z)  =  XY v not(X)Z 
	g(X,Y,Z)  =  XY v XZ v YZ 
	h(X,Y,Z)  =  X xor Y xor Z 

In each bit position f acts as a conditional: if x then y else z.
(The function f could have been defined using + instead of v since XY
and not(X)Z will never have 1's in the same bit position.)  In each
bit position g acts as a majority function: if at least two of x, y, z
are on, then g has a one in that bit position, else g has a zero. It
is interesting to note that if the bits of X, Y, and Z are independent
and unbiased, the each bit of f(X,Y,Z) will be independent and
unbiased, and similarly each bit of g(X,Y,Z) will be independent and
unbiased.  The function h is the bit-wise ``xor'' or ``parity'' function;
it has properties similar to those of f and g.

Do the following:

For i = 0 to N/16-1 do	/* process each 16-word block */
	For j = 0 to 15 do: /* copy block i into X */
	  Set X[j] to M[i*16+j].
	end /* of loop on j */
	Save A as AA, B as BB, C as CC, and D as DD.

	[Round 1]
	  Let [A B C D i s] denote the operation
		A = (A + f(B,C,D) + X[i]) <<< s  .
	  Do the following 16 operations:
		[A B C D 0 3] 
		[D A B C 1 7] 
		[C D A B 2 11] 
		[B C D A 3 19] 
		[A B C D 4 3] 
		[D A B C 5 7] 
		[C D A B 6 11] 
		[B C D A 7 19] 
		[A B C D 8 3] 
		[D A B C 9 7] 
		[C D A B 10 11] 
		[B C D A 11 19] 
		[A B C D 12 3] 
		[D A B C 13 7] 
		[C D A B 14 11] 
		[B C D A 15 19] 

	[Round 2]
	  Let [A B C D i s] denote the operation
	    	A = (A + g(B,C,D) + X[i] + 5A827999) <<< s .
	  (The value 5A..99 is a hexadecimal 32-bit constant, written with
	  the high-order digit first. This constant represents the square
	  root of 2.  The octal value of this constant is 013240474631.
          See Knuth, The Art of Programming, Volume 2
	  (Seminumerical Algorithms), Second Edition (1981), Addison-Wesley.
	  Table 2, page 660.)
	  Do the following 16 operations:
		[A B C D 0  3] 
		[D A B C 4  5] 
		[C D A B 8  9] 
		[B C D A 12 13] 
		[A B C D 1  3] 
		[D A B C 5  5] 
		[C D A B 9  9] 
		[B C D A 13 13] 
		[A B C D 2  3] 
		[D A B C 6  5] 
		[C D A B 10 9] 
		[B C D A 14 13] 
		[A B C D 3  3] 
		[D A B C 7  5] 
		[C D A B 11 9] 
		[B C D A 15 13] 

	[Round 3]
	  Let [A B C D i s] denote the operation
		A = (A + h(B,C,D) + X[i] + 6ED9EBA1) <<< s
	  (The value 6E..A1 is a hexadecimal 32-bit constant, written with
	  the high-order digit first. This constant represents the square
	  root of 3.  The octal value of this constant is 015666365641.
          See Knuth, The Art of Programming, Volume 2
	  (Seminumerical Algorithms), Second Edition (1981), Addison-Wesley.
	  Table 2, page 660.)
	  Do the following 16 operations:
		[A B C D 0  3] 
		[D A B C 8  9] 
		[C D A B 4  11] 
		[B C D A 12 15] 
		[A B C D 2  3] 
		[D A B C 10 9] 
		[C D A B 6  11] 
		[B C D A 14 15] 
		[A B C D 1  3] 
		[D A B C 9  9] 
		[C D A B 5  11] 
		[B C D A 13 15] 
		[A B C D 3  3] 
		[D A B C 11 9] 
		[C D A B 7  11] 
		[B C D A 15 15] 

Then perform the following additions:
		A = A + AA
		B = B + BB
		C = C + CC
		D = D + DD
(That is, each of the four registers is incremented by the value it had
before this block was started.)

end /* of loop on i */


Step 5. Output
--------------

The message digest produced as output is A,B,C,D.
That is, we begin with the low-order byte of A, and end with the
high-order byte of D.

This completes the description of MD4.  A reference implementation in
C is given in the Appendix.


III. Extensions
---------------

If more than 128 bits of output are required, then the following
procedure is recommended to obtain a 256-bit output.  (There is no
provision made for obtaining more than 256 bits.)

Two copies of MD4 are run in parallel over the input.  The first copy
is standard as described above.  The second copy is modified as follows.

The initial state of the second copy is:
	word A:    00 11 22 33
	word B:    44 55 66 77
	word C:    88 99 aa bb
	word D:    cc dd ee ff

The magic constants in rounds 2 and 3 for the second copy of MD4 are
changed from sqrt(2) and sqrt(3) to cuberoot(2) and cuberoot(3):
				Octal		Hex
	Round 2 constant	012050505746	50a28be6 
	Round 3 constant	013423350444    5c4dd124

Finally, after every 16-word block is processed (including the last
block), the values of the A registers in the two copies are exchanged.

The final message digest is obtaining by appending the result of the
second copy of MD4 to the end of the result of the first copy of MD4.


IV. Summary
------------

The MD4 message digest algorithm is simple to implement, and provides
a ``fingerprint'' or message digest of a message of arbitrary length.

It is conjectured that the difficulty of coming up with two messages
having the same message digest is on the order of 2^64 operations, and
that the difficulty of coming up with any message having a given
message digest is on the order of 2^128 operations.  The MD4 algorithm
has been carefully scrutinized for weaknesses.  It is, however, a
relatively new algorithm and further security analysis is of course
justified, as is the case with any new proposal of this sort.  The
level of security provided by MD4 should be sufficient for
implementing very high security hybrid digital signature schemes based
on MD4 and the RSA public-key cryptosystem.

V. Acknowledgements
-------------------

I'd like to thank Don Coppersmith, Burt Kaliski, Ralph Merkle, and
Noam Nisan for numerous helpful comments and suggestions.


APPENDIX. Reference Implementation
----------------------------------

This appendix contains the following files:
	md4.h		-- a header file for using the MD4 implementation
	md4.c		-- the source code for the MD4 routines
	md4driver.c	-- a sample ``user'' routine
	session		-- sample results of running md4driver
#endif


/*
**
**  The following code has been modified (mostly by deleting parts
 The routine Md4Block
**  is designed to hash a single block, and cuts out all
**  the stuff required for hashing inputs of arbitrary lengths.
**  This makes it much faster and simpler for this application.
**
**  Modified 90.03.12 by Ralph C. Merkle
*/

/*  Original header and credit to RSA Data Security and Ron Rivest  */
/*
** **************************************************************************
** md4.c -- Implementation of MD4 Message Digest Algorithm                 **
** Updated: 2/16/90 by Ronald L. Rivest                                    **
** (C) 1990 RSA Data Security, Inc.                                        **
** **************************************************************************
*/
 

/* Compile-time declarations of MD4 ``magic constants''.
*/
#define I0  0x67452301       /* Initial values for MD buffer */
#define I1  0xefcdab89
#define I2  0x98badcfe
#define I3  0x10325476
#define C2  013240474631     /* round 2 constant = sqrt(2) in octal */
#define C3  015666365641     /* round 3 constant = sqrt(3) in octal */
/* C2 and C3 are from Knuth, The Art of Programming, Volume 2
** (Seminumerical Algorithms), Second Edition (1981), Addison-Wesley.
** Table 2, page 660.
*/
#define fs1  3               /* round 1 shift amounts */
#define fs2  7   
#define fs3 11  
#define fs4 19  
#define gs1  3               /* round 2 shift amounts */
#define gs2  5   
#define gs3  9   
#define gs4 13  
#define hs1  3               /* round 3 shift amounts */
#define hs2  9 
#define hs3 11 
#define hs4 15


/* Compile-time macro declarations for MD4.
** Note: The ``rot'' operator uses the variable ``tmp''.
** It assumes tmp is declared as unsigned, so that the >>
** operator will shift in zeros rather than extending the sign bit.
*/
#define	f(X,Y,Z)             ((X&Y) | ((~X)&Z))
#define	g(X,Y,Z)             ((X&Y) | (X&Z) | (Y&Z))
#define h(X,Y,Z)             (X^Y^Z)
#define rot(X,S)             (tmp=X,(tmp<<S) | (tmp>>(32-S)))
#define ff(A,B,C,D,i,s)      A = rot((A + f(B,C,D) + X[i]),s)
#define gg(A,B,C,D,i,s)      A = rot((A + g(B,C,D) + X[i] + C2),s)
#define hh(A,B,C,D,i,s)      A = rot((A + h(B,C,D) + X[i] + C3),s)

typedef unsigned long int word32;

extern void ErrAbort();

void 
Md4Block(output, outputSize, input, inputSize)
word32 output[];
int outputSize;
word32 input[];
int inputSize;
{
  int i;
  word32 X[16];
  register word32 tmp, A, B, C, D;

/*  copy input into X vector */
  for(i=0; i<inputSize; i++)
	X[i] = input[i];

/*  zero out rest of X vector */
  for(   ; i<16; i++)
	X[i] = 0;

  A = I0;
  B = I1;
  C = I2;
  D = I3;
  /* Update the message digest buffer */
  ff(A , B , C , D ,  0 , fs1); /* Round 1 */
  ff(D , A , B , C ,  1 , fs2); 
  ff(C , D , A , B ,  2 , fs3); 
  ff(B , C , D , A ,  3 , fs4); 
  ff(A , B , C , D ,  4 , fs1); 
  ff(D , A , B , C ,  5 , fs2); 
  ff(C , D , A , B ,  6 , fs3); 
  ff(B , C , D , A ,  7 , fs4); 
  ff(A , B , C , D ,  8 , fs1); 
  ff(D , A , B , C ,  9 , fs2); 
  ff(C , D , A , B , 10 , fs3); 
  ff(B , C , D , A , 11 , fs4); 
  ff(A , B , C , D , 12 , fs1); 
  ff(D , A , B , C , 13 , fs2); 
  ff(C , D , A , B , 14 , fs3); 
  ff(B , C , D , A , 15 , fs4); 
  gg(A , B , C , D ,  0 , gs1); /* Round 2 */
  gg(D , A , B , C ,  4 , gs2); 
  gg(C , D , A , B ,  8 , gs3); 
  gg(B , C , D , A , 12 , gs4); 
  gg(A , B , C , D ,  1 , gs1); 
  gg(D , A , B , C ,  5 , gs2); 
  gg(C , D , A , B ,  9 , gs3); 
  gg(B , C , D , A , 13 , gs4); 
  gg(A , B , C , D ,  2 , gs1); 
  gg(D , A , B , C ,  6 , gs2); 
  gg(C , D , A , B , 10 , gs3); 
  gg(B , C , D , A , 14 , gs4); 
  gg(A , B , C , D ,  3 , gs1); 
  gg(D , A , B , C ,  7 , gs2); 
  gg(C , D , A , B , 11 , gs3); 
  gg(B , C , D , A , 15 , gs4);  
  hh(A , B , C , D ,  0 , hs1); /* Round 3 */
  hh(D , A , B , C ,  8 , hs2); 
  hh(C , D , A , B ,  4 , hs3); 
  hh(B , C , D , A , 12 , hs4); 
  hh(A , B , C , D ,  2 , hs1); 
  hh(D , A , B , C , 10 , hs2); 
  hh(C , D , A , B ,  6 , hs3); 
  hh(B , C , D , A , 14 , hs4); 
  hh(A , B , C , D ,  1 , hs1); 
  hh(D , A , B , C ,  9 , hs2); 
  hh(C , D , A , B ,  5 , hs3); 
  hh(B , C , D , A , 13 , hs4); 
  hh(A , B , C , D ,  3 , hs1); 
  hh(D , A , B , C , 11 , hs2); 
  hh(C , D , A , B ,  7 , hs3); 
  hh(B , C , D , A , 15 , hs4);

/*  dropped the increment, too.  For a single block, it doesn't
**  make any difference.  RCM.
*/

  if(outputSize == 0) return;
  output[0] = A;
  if(outputSize == 1) return;
  output[1] = B;
  if(outputSize == 2) return;
  output[2] = C;
  if(outputSize == 3) return;
  output[3] = D;
  if(outputSize == 4) return;
  ErrAbort("bad outputSize to md4");
}



