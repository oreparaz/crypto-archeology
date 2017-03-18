/*
 * This file contains some of the hash methods and hash-function
 * specific information.  At the present time, it includes a
 * very slow and inefficient implementation of Snefru.  It calls
 * MD4, the implementation of which is included in another file.
 * Further hash functions can be added in the future as warranted.
 * Please contact Ralph C. Merkle before doing so to insure that the
 * constant value assigned to the new hash method is unique and does
 * not collide with other values.  In any event, values below 100
 * are reserved for use by Xerox.
 */
/*
  Copyright (c) Xerox Corporation 1990.  All rights reserved.
  
  The following notices apply to the implementation of Snefru and
  related software contained in this file.  They do not apply
  to the other files included with this software, which include
  implementations of MD4 and of the Abstract Xerox Hash Signature.
  Please refer to the appropriate notices.

  License to copy and use this software (an implementation of Snefru)
  is granted provided that it is identified as the "Xerox Secure Hash
  Function" in all material mentioning or referencing this software
  or this hash function.
  
  License is also granted to make and use derivative works provided that such
  works are identified as "derived from the Xerox Secure Hash Function" in
  all material mentioning or referencing the derived work.

  XEROX CORPORATION MAKES NO REPRESENTATIONS CONCERNING EITHER THE
  MERCHANTABILITY OF THIS SOFTWARE OR THE SUITABILITY OF THIS SOFTWARE FOR
  ANY PARTICULAR PURPOSE.  IT IS PROVIDED "AS IS" WITHOUT EXPRESS OR IMPLIED
  WARRANTY OF ANY KIND.
  
  These notices must be retained in any copies of any part of this software.
  
  Updated information about Snefru is available from arisia.xerox.com in
  directory /pub/hash by anonymous FTP.  The README file provides a quick
  introduction to the subdirectories.
*/
#include <stdio.h>
#define MAX_INPUT_BLOCK_SIZE 16
#define SNEFRU_INPUT_BLOCK_SIZE 16
#define OUTPUT_BLOCK_SIZE 8
#define MAX_SBOX_COUNT 8
#define MD4_METHOD 100
#define SNEFRU3_METHOD 3
#define SNEFRU4_METHOD 4
#define SNEFRU512_INPUT_BLOCK_SIZE 16
#define SNEFRU384_INPUT_BLOCK_SIZE 12
#define SNEFRU256_INPUT_BLOCK_SIZE 8
#define SNEFRU128_INPUT_BLOCK_SIZE 4
#define DEBUG_SNEFRU 0

#define round512(L,C,N,SB)	SBE=SB[C&0xffL];L^=SBE;N^=SBE
#define rotate512(B)	B=(B>>shift) | (B<<leftShift)

extern void ErrAbort();
extern void Copy();
extern void Md4Block();
extern void PrintIt();
extern void Increment64BitCounter();

typedef unsigned long int word32;
int     shiftTable[4] = {16, 8, 16, 24};

/* The standard S boxes must be defined in another file */
extern word32 standardSBoxes[MAX_SBOX_COUNT][256];

void    SnefruBlock (output, outputBlockSize,
		input, inputBlockSize, securityLevel)
	word32 output[/* outputBlockSize */];
	int outputBlockSize;
	word32 input[/* inputBlockSize */];
	int     inputBlockSize;
	int     securityLevel;
{

	/* holds the array of data being hashed  */
	word32 block[MAX_INPUT_BLOCK_SIZE];
	word32 SBoxEntry;	/* just a temporary */
	int     shift;
	int     i;
	int     index;
	int     next, last;
	int     byteInWord;

	/* Test for various error conditions and logic problems  */
	if (securityLevel * 2 > MAX_SBOX_COUNT)
		ErrAbort ("Too few S-boxes");
	if (outputBlockSize < 2)
		ErrAbort (" outputBlockSize too small");
	if ( outputBlockSize > inputBlockSize)
		ErrAbort ("logic error, outputBlockSize is too big");

	/* initialize the block to be hashed from the input  */
	Copy(block, input, inputBlockSize);
	/*  increase block size till it's a multiple of 4 words
	    and pad the new words with 0's */
	while ( (inputBlockSize & 3) != 0 )
		block[inputBlockSize++] = 0L;

	/*  complete error testing with updated inputBlockSize  */
	if ( (outputBlockSize+2) > inputBlockSize)
		ErrAbort ("logic error, inputBlockSize is too small");
	if (inputBlockSize > MAX_INPUT_BLOCK_SIZE)
		ErrAbort ("Logic error, inputBlockSize > MAX_INPUT_BLOCK_SIZE");
	/* All the error conditions have now been checked -- everything should
	   work smoothly  */
	/* Note that we are computing securityLevel * inputBlockSize * 4
	   rounds.  */
	for (index = 0; index < securityLevel; index++) {


		for (byteInWord = 0; byteInWord < 4; byteInWord++) {


			for (i = 0; i < inputBlockSize; i++) {
				
				next = (i + 1) % inputBlockSize;
				/*  last = (i-1) MOD inputBlockSize */
				last = (i + inputBlockSize - 1) %
					inputBlockSize;


				SBoxEntry = standardSBoxes
					[2 * index + ((i / 2) & 1)]
					[block[i] & 0xff];
				block[next] ^= SBoxEntry;
				block[last] ^= SBoxEntry;
			};


			/* Rotate right all 32-bit words in the entire block
			   at once.  */
			shift = shiftTable[byteInWord];
			for (i = 0; i < inputBlockSize; i++)
				block[i] =	(block[i] >> shift) |
						(block[i] << (32 - shift));


		};		/* end of byteInWord going from 0 to 3 */


	};			/* end of index going from 0 to
				   securityLevel-1 */



	for (i = 0; i < outputBlockSize; i++)
		output[i] = input[i] ^ block[inputBlockSize - 1 - i];


}


/*
 * Snefru512 is a more efficient and specialized version of SnefruBlock.
 * It accepts an input of 16 32-bit words and produces an output of
 * 32-bit words.  The output size cannot be bigger than 14 32-bit words,
 * or a serious degradation in security will occur.
 */
void
Snefru512 (output, outputBlockSize, input, inputBlockSize, securityLevel)
	word32	output[];
	int	outputBlockSize;
	word32	input[SNEFRU512_INPUT_BLOCK_SIZE];
	int	inputBlockSize;
	int	securityLevel;
{
	static int shiftTable[4] = {16, 8, 16, 24};
	/* the array of data being hashed  */
	word32	SBE;	/* just a temporary */
	int     shift, leftShift;
	int     index;
	int     byteInWord;
	word32	*SBox0;
	word32	*SBox1;
	word32	B00,B01,B02,B03,B04,B05,B06,B07,B08,B09,B10,B11,B12,B13,B14,B15;

	/* initialize the block to be hashed from the input  */
	B00 = input[0];
	B01 = input[1];
	B02 = input[2];
	B03 = input[3];
	B04 = input[4];
	B05 = input[5];
	B06 = input[6];
	B07 = input[7];
	B08 = input[8];
	B09 = input[9];
	B10 = input[10];
	B11 = input[11];
	B12 = 0;
	B13 = 0;
	B14 = 0;
	B15 = 0;
	switch (inputBlockSize) {
	case 16:	B15 = input[15];
	case 15:	B14 = input[14];
	case 14:	B13 = input[13];
	case 13:	B12 = input[12];
		break;
	default:	ErrAbort("bad input size to snefru512");
	};

	for (index = 0; index < securityLevel; index++) {
		SBox0 = standardSBoxes[2*index+0];
		SBox1 = standardSBoxes[2*index+1];
		for (byteInWord = 0; byteInWord < 4; byteInWord++) {
			round512(B15,B00,B01,SBox0);
			round512(B00,B01,B02,SBox0);
			round512(B01,B02,B03,SBox1);
			round512(B02,B03,B04,SBox1);
			round512(B03,B04,B05,SBox0);
			round512(B04,B05,B06,SBox0);
			round512(B05,B06,B07,SBox1);
			round512(B06,B07,B08,SBox1);
			round512(B07,B08,B09,SBox0);
			round512(B08,B09,B10,SBox0);
			round512(B09,B10,B11,SBox1);
			round512(B10,B11,B12,SBox1);
			round512(B11,B12,B13,SBox0);
			round512(B12,B13,B14,SBox0);
			round512(B13,B14,B15,SBox1);
			round512(B14,B15,B00,SBox1);
			/*
			 * Rotate right all 32-bit words in the entire block
			 * at once.
			 */
			shift = shiftTable[byteInWord];
			leftShift = 32-shift;
			rotate512(B00);
			rotate512(B01);
			rotate512(B02);
			rotate512(B03);
			rotate512(B04);
			rotate512(B05);
			rotate512(B06);
			rotate512(B07);
			rotate512(B08);
			rotate512(B09);
			rotate512(B10);
			rotate512(B11);
			rotate512(B12);
			rotate512(B13);
			rotate512(B14);
			rotate512(B15);
		};		/* end of byteInWord going from 0 to 3 */
	};			/* end of index going from 0 to
				 * securityLevel-1 */

	switch (outputBlockSize) {
	case 14:	output[13] = input[13] ^ B02;
	case 13:	output[12] = input[12] ^ B03;
	case 12:	output[11] = input[11] ^ B04;
	case 11:	output[10] = input[10] ^ B05;
	case 10:	output[ 9] = input[ 9] ^ B06;
	case  9:	output[ 8] = input[ 8] ^ B07;
	case  8:	output[ 7] = input[ 7] ^ B08;
	case  7:	output[ 6] = input[ 6] ^ B09;
	case  6:	output[ 5] = input[ 5] ^ B10;
	case  5:	output[ 4] = input[ 4] ^ B11;
	case  4:	output[ 3] = input[ 3] ^ B12;
	case  3:	output[ 2] = input[ 2] ^ B13;
	case  2:	output[ 1] = input[ 1] ^ B14;
	case  1:	output[ 0] = input[ 0] ^ B15;
			break;
	default: ErrAbort("Bad output block size");
	};
};

/*
 * Snefru384 is a more efficient and specialized version of SnefruBlock.
 * It accepts an input of 12 32-bit words and produces an output of
 * outputBlockSize 32-bit words.  The output size cannot be bigger
 * than 10 32-bit words, or a serious degradation in security will occur.
 */
void
Snefru384 (output, outputBlockSize, input, inputBlockSize, securityLevel)
	word32	output[];
	int	outputBlockSize;
	word32	input[SNEFRU384_INPUT_BLOCK_SIZE];
	int	inputBlockSize;
	int	securityLevel;
{
	static int shiftTable[4] = {16, 8, 16, 24};
	/* the array of data being hashed  */
	word32	SBE;	/* just a temporary */
	int     shift, leftShift;
	int     index;
	int     byteInWord;
	word32	*SBox0;
	word32	*SBox1;
	word32	B00,B01,B02,B03,B04,B05,B06,B07,B08,B09,B10,B11;

	/* initialize the block to be hashed from the input  */
	B00 = input[0];
	B01 = input[1];
	B02 = input[2];
	B03 = input[3];
	B04 = input[4];
	B05 = input[5];
	B06 = input[6];
	B07 = input[7];
	B08 = 0;
	B09 = 0;
	B10 = 0;
	B11 = 0;
	switch (inputBlockSize) {
	case 12:	B11 = input[11];
	case 11:	B10 = input[10];
	case 10:	B09 = input[9];
	case  9:	B08 = input[8];
		break;
	default:	ErrAbort("bad input size to snefru384");
	};



	for (index = 0; index < securityLevel; index++) {
		SBox0 = standardSBoxes[2*index+0];
		SBox1 = standardSBoxes[2*index+1];
		for (byteInWord = 0; byteInWord < 4; byteInWord++) {
			round512(B11,B00,B01,SBox0);
			round512(B00,B01,B02,SBox0);
			round512(B01,B02,B03,SBox1);
			round512(B02,B03,B04,SBox1);
			round512(B03,B04,B05,SBox0);
			round512(B04,B05,B06,SBox0);
			round512(B05,B06,B07,SBox1);
			round512(B06,B07,B08,SBox1);
			round512(B07,B08,B09,SBox0);
			round512(B08,B09,B10,SBox0);
			round512(B09,B10,B11,SBox1);
			round512(B10,B11,B00,SBox1);
			/*
			 * Rotate right all 32-bit words in the entire block
			 * at once.
			 */
			shift = shiftTable[byteInWord];
			leftShift = 32-shift;
			rotate512(B00);
			rotate512(B01);
			rotate512(B02);
			rotate512(B03);
			rotate512(B04);
			rotate512(B05);
			rotate512(B06);
			rotate512(B07);
			rotate512(B08);
			rotate512(B09);
			rotate512(B10);
			rotate512(B11);
		};		/* end of byteInWord going from 0 to 3 */
	};			/* end of index going from 0 to
				 * securityLevel-1 */

	switch (outputBlockSize) {
	case 10:	output[ 9] = input[ 9] ^ B02;
	case  9:	output[ 8] = input[ 8] ^ B03;
	case  8:	output[ 7] = input[ 7] ^ B04;
	case  7:	output[ 6] = input[ 6] ^ B05;
	case  6:	output[ 5] = input[ 5] ^ B06;
	case  5:	output[ 4] = input[ 4] ^ B07;
	case  4:	output[ 3] = input[ 3] ^ B08;
	case  3:	output[ 2] = input[ 2] ^ B09;
	case  2:	output[ 1] = input[ 1] ^ B10;
	case  1:	output[ 0] = input[ 0] ^ B11;
			break;
	default: ErrAbort("Bad output block size");
	};
};


/*
 * Snefru256 is a more efficient and specialized version of SnefruBlock.
 * It accepts an input of 8 32-bit words and produces an output of
 * outputBlockSize 32-bit words.  The output size cannot be bigger
 * than 6 32-bit words, or a serious degradation in security will occur.
 */
void
Snefru256 (output, outputBlockSize, input, inputBlockSize, securityLevel)
	word32	output[];
	int	outputBlockSize;
	word32	input[SNEFRU256_INPUT_BLOCK_SIZE];
	int	inputBlockSize;
	int	securityLevel;
{
	static int shiftTable[4] = {16, 8, 16, 24};
	/* the array of data being hashed  */
	word32	SBE;	/* just a temporary */
	int     shift, leftShift;
	int     index;
	int     byteInWord;
	word32	*SBox0;
	word32	*SBox1;
	word32	B00,B01,B02,B03,B04,B05,B06,B07;

	/* initialize the block to be hashed from the input  */
	B00 = input[0];
	B01 = input[1];
	B02 = input[2];
	B03 = input[3];
	B04 = 0;
	B05 = 0;
	B06 = 0;
	B07 = 0;
	switch (inputBlockSize) {
	case 8:	B07 = input[7];
	case 7:	B06 = input[6];
	case 6:	B05 = input[5];
	case 5:	B04 = input[4];
		break;
	default:	ErrAbort("bad input size to snefru256");
	};


	for (index = 0; index < securityLevel; index++) {
		SBox0 = standardSBoxes[2*index+0];
		SBox1 = standardSBoxes[2*index+1];
		for (byteInWord = 0; byteInWord < 4; byteInWord++) {
			round512(B07,B00,B01,SBox0);
			round512(B00,B01,B02,SBox0);
			round512(B01,B02,B03,SBox1);
			round512(B02,B03,B04,SBox1);
			round512(B03,B04,B05,SBox0);
			round512(B04,B05,B06,SBox0);
			round512(B05,B06,B07,SBox1);
			round512(B06,B07,B00,SBox1);
			/*
			 * Rotate right all 32-bit words in the entire block
			 * at once.
			 */
			shift = shiftTable[byteInWord];
			leftShift = 32-shift;
			rotate512(B00);
			rotate512(B01);
			rotate512(B02);
			rotate512(B03);
			rotate512(B04);
			rotate512(B05);
			rotate512(B06);
			rotate512(B07);
		};		/* end of byteInWord going from 0 to 3 */
	};			/* end of index going from 0 to
				 * securityLevel-1 */

	switch (outputBlockSize) {
	case  6:	output[ 5] = input[ 5] ^ B02;
	case  5:	output[ 4] = input[ 4] ^ B03;
	case  4:	output[ 3] = input[ 3] ^ B04;
	case  3:	output[ 2] = input[ 2] ^ B05;
	case  2:	output[ 1] = input[ 1] ^ B06;
	case  1:	output[ 0] = input[ 0] ^ B07;
			break;
	default: ErrAbort("Bad output block size");
	};
};

/*
 * Snefru128 is a more efficient and specialized version of SnefruBlock.
 * It accepts an input of 4 32-bit words and produces an output of
 * 32-bit words.  The output size cannot be bigger than 2 32-bit words,
 * or a serious degradation in security will occur.
 */
void
Snefru128 (output, outputBlockSize, input, inputBlockSize, securityLevel)
	word32	output[];
	int	outputBlockSize;
	word32	input[SNEFRU128_INPUT_BLOCK_SIZE];
	int	inputBlockSize;
	int	securityLevel;
{
	static int shiftTable[4] = {16, 8, 16, 24};
	/* the array of data being hashed  */
	word32	SBE;	/* just a temporary */
	int     shift, leftShift;
	int     index;
	int     byteInWord;
	word32	*SBox0;
	word32	*SBox1;
	word32	B00,B01,B02,B03;

	/* initialize the block to be hashed from the input  */
	B00 = 0;
	B01 = 0;
	B02 = 0;
	B03 = 0;
	switch (inputBlockSize) {
	case 4:	B03 = input[3];
	case 3:	B02 = input[2];
	case 2:	B01 = input[1];
	case 1:	B00 = input[0];
		break;
	default:	ErrAbort("bad input size to snefru128");
	};


	for (index = 0; index < securityLevel; index++) {
		SBox0 = standardSBoxes[2*index+0];
		SBox1 = standardSBoxes[2*index+1];
		for (byteInWord = 0; byteInWord < 4; byteInWord++) {
			round512(B03,B00,B01,SBox0);
			round512(B00,B01,B02,SBox0);
			round512(B01,B02,B03,SBox1);
			round512(B02,B03,B00,SBox1);
			/*
			 * Rotate right all 32-bit words in the entire block
			 * at once.
			 */
			shift = shiftTable[byteInWord];
			leftShift = 32-shift;
			rotate512(B00);
			rotate512(B01);
			rotate512(B02);
			rotate512(B03);
		};		/* end of byteInWord going from 0 to 3 */
	};			/* end of index going from 0 to
				 * securityLevel-1 */

	switch (outputBlockSize) {
	case  2:	output[ 1] = input[ 1] ^ B02;
	case  1:	output[ 0] = input[ 0] ^ B03;
			break;
	default: ErrAbort("Bad output block size");
	};
};

/*
 * HashAny is just a switching routine.  It calls the appropriate
 * hash function
 */
void    HashAny (output, outputBlockSize, input, inputBlockSize, hashMethod)
	word32 output[/* outputBlockSize */];
	int outputBlockSize;
	word32 input[/* inputBlockSize */];
	int     inputBlockSize;
	int     hashMethod;
{
#if DEBUG_SNEFRU
	/* Yes, dimension testOutput with the max INPUT size --
	 * the input block size is guaranteed to be larger, and
	 * sometimes someone pushes the output size...
	 */
	word32	testOutput[MAX_INPUT_BLOCK_SIZE];
	int	i;
#endif

	static int	flag = 0;

	switch ( hashMethod ) {
		case MD4_METHOD:
			Md4Block(output, outputBlockSize,
				input, inputBlockSize);
			return;
		case SNEFRU3_METHOD:
		case SNEFRU4_METHOD:
			switch (inputBlockSize) {
			default: {
				if (flag == 0) {
					flag = 1;
					printf(
		"Efficiency warning: using SnefruBlock (slow routine)\n");
				};
				SnefruBlock(output, outputBlockSize,
				input, inputBlockSize, hashMethod);
				return;
				};
			case  1:
			case  2:
			case  3:
			case  4:

					Snefru128(output, outputBlockSize,
					input, inputBlockSize, hashMethod);
					break;
			case  5:
			case  6:
			case  7:
			case  8:

					Snefru256(output, outputBlockSize,
					input, inputBlockSize, hashMethod);
					break;

			case   9:
			case  10:
			case  11:
			case  12:

					Snefru384(output, outputBlockSize,
					input, inputBlockSize, hashMethod);
					break;
			case 13:
			case 14:
			case 15:
			case 16:

					Snefru512(output, outputBlockSize,
					input, inputBlockSize, hashMethod);
					break;
				};
/* Testing code -- if you want to verify the faster implementations
 * of Snefru put this code back in place.  It's painfully slow....
 */
#if DEBUG_SNEFRU
	SnefruBlock(testOutput, outputBlockSize,
		input, inputBlockSize, hashMethod);
	for (i=0; i<outputBlockSize; i++)
		if(testOutput[i] != output[i]) {
			PrintIt("input =",input,   inputBlockSize);
			PrintIt("output=",output, outputBlockSize);
			PrintIt("testOutput=", testOutput, outputBlockSize);
			ErrAbort("Bad Snefru hash");
		};
#endif
			break;
		default:
			ErrAbort("Bad hash method specifier");
		};
}

/*  The following routine is a variant of HashAny which expects
    to generate more output bits than input bits.  That is,
    outputBlockSize is larger than inputBlockSize.  It is used
    to expand a small amount of random information into a large
    amount of pseudo-random information.
*/
void    HashExpand (
	outputBlock, outputBlockSize,
	inputBlock, inputBlockSize,
	hashMethod)
word32 outputBlock[/* outputBlockSize */];
int outputBlockSize;
word32 inputBlock[/* inputBlockSize */];
int     inputBlockSize;
int     hashMethod;
{
	int i;
	word32 tempBlock[MAX_INPUT_BLOCK_SIZE];
	int tempOutputSize;
	int tempInputSize;

	if (inputBlockSize >= MAX_INPUT_BLOCK_SIZE)
		ErrAbort("inputBlockSize too large in HashExpand");
	Copy (&tempBlock[1], inputBlock, inputBlockSize);
	for (i=inputBlockSize+1; i<MAX_INPUT_BLOCK_SIZE; i++)
		tempBlock[i]=0;
	switch ( hashMethod ) {
		case MD4_METHOD:
			tempInputSize  = 16;
			tempOutputSize = 4;
			break;
		case SNEFRU3_METHOD:
		case SNEFRU4_METHOD:
			tempInputSize  = MAX_INPUT_BLOCK_SIZE;
			tempOutputSize = MAX_INPUT_BLOCK_SIZE-2;
			break;
		default:
			ErrAbort("Bad hash method specifier");
		};
	if (inputBlockSize >= tempInputSize)
 				ErrAbort("input to HashExpand too large");
	for(i=0; i < outputBlockSize; i += tempOutputSize)  {
		if (tempOutputSize > outputBlockSize-i)
			tempOutputSize = outputBlockSize-i;
		tempBlock[0]=i;
		HashAny(&outputBlock[i], tempOutputSize,
			tempBlock, tempInputSize, hashMethod);
		};
}



/*  internal diagnostics. Make sure the S-Boxes aren't
messed up, that the one-way hash function is correct, etc. */
void DoSelfTest(testingLevel)
	int	testingLevel;
{
	int     i;

	if (testingLevel <= 0) return;
	/* Test the standard S boxes to make sure they haven't been
	   damaged.  */
	/* Test to make sure each column is a permutation.  */
	for (i = 0; i < MAX_SBOX_COUNT; i++) {
		char    testArray[256];
		int     testShift = 0;
		int     j;

		for (testShift = 0; testShift < 32; testShift += 8) {
			for (j = 0; j < 256; j++)
				testArray[j] = 0;
			for (j = 0; j < 256; j++)
				testArray[(standardSBoxes[i][j] >>
					testShift) & 0xff]++;
			for (j = 0; j < 256; j++)
				if (testArray[j] != 1)
					ErrAbort
			("Table error -- the standard S box is corrupted");
		};
	};
	/* Okay, the standard S-box hasn't been damaged  */



	/* Now try hashing something.  */
	{
		word32 testInput[MAX_INPUT_BLOCK_SIZE];
		word32 testOutput[OUTPUT_BLOCK_SIZE];
		int     j;
		int	k;


		if (OUTPUT_BLOCK_SIZE != 8)
			ErrAbort ("The output block size has changed, update the self-test");
		if (MAX_INPUT_BLOCK_SIZE != 16)
			ErrAbort ("The input block size has changed, update the self-test");
		if (MAX_SBOX_COUNT != 8)
			ErrAbort ("Wrong number of S boxes, update the self-test");

		for (i = 0; i < MAX_INPUT_BLOCK_SIZE; i++)
			testInput[i] = 0;	/* zero the input */
		k = 0;  /*  zero the pointer into the input buffer */
		for (i = 0; i < 50; i++) {
			SnefruBlock (testOutput, 8, testInput,16, 4);
			/*	Copy the output into a new slot in the input buffer */
			for (j = 0; j < OUTPUT_BLOCK_SIZE; j++)
				testInput[k+j] = testOutput[j];
			k += OUTPUT_BLOCK_SIZE;
				/*	reset pointer into input buffer
					if it might overflow next time */
			if ( (k+OUTPUT_BLOCK_SIZE) > MAX_INPUT_BLOCK_SIZE) k=0;
		};
		if (	(testOutput[0] != 0x754D12FBL)	||
			(testOutput[1] != 0xA04197D2L)	||
			(testOutput[2] != 0xE92A9C7EL)	||
			(testOutput[3] != 0x4298FF88L)	||
			(testOutput[4] != 0xFCA820CFL)	||
			(testOutput[5] != 0x344FDDE6L)	||
			(testOutput[6] != 0x424DD3CAL)	||
			(testOutput[7] != 0x135EFF62L)  )
			ErrAbort ("Test hash of 64 bytes of 0 failed");
	};
	/* Okay, we can hash at least 50  64-byte values correctly.  */
}


/*
 * The following routine accepts, as input, a file name.
 * The contents of the file are hashed, and the hash result
 * is put into "hashValue".
 */
void
SnefruHashFile (inputFile, hashValue, hashValueSize, securityLevel)
	FILE	*inputFile;
	word32	hashValue[];
	int	hashValueSize;
	int	securityLevel;
{	int     i;
	word32 hash[SNEFRU_INPUT_BLOCK_SIZE];
	int	chunkSize;
	word32 bitCount[2];	/* the 64-bit count of the number of
					 * bits in the input */
	long int byteCount;	/* the count of the number of bytes we just
				 * read */

	if (hashValueSize >= SNEFRU_INPUT_BLOCK_SIZE)
		ErrAbort("hashValueSize >= SNEFRU_INPUT_BLOCK_SIZE");
	bitCount[0] = 0;
	bitCount[1] = 0;
	for (i = 0; i < SNEFRU_INPUT_BLOCK_SIZE; i++)
		hash[i] = 0;	/* initialize hash  */
	/*
	 * Hash each chunk in the input and keep the result in hash.
	 * Note that the first 16 (32) bytes of hash holds the output
	 * of the previous hash
	 * computation done during the previous iteration of the loop
	 */
	chunkSize = SNEFRU_INPUT_BLOCK_SIZE - hashValueSize;
	do {
		/* Get the next chunk */
		byteCount = ReadChunk (inputFile, &hash[hashValueSize],
			chunkSize);
		Increment64BitCounter (bitCount, 8*byteCount);
		/* hash in the block we just read  */
		if (byteCount > 0)
			Snefru512 (hash, hashValueSize,
				hash, SNEFRU_INPUT_BLOCK_SIZE, securityLevel);
	} while (byteCount > 0);  /* end of while */

	/*
	 * Put the 64-bit bit-count into the final 64-bits of the block about
	 * to be hashed
	 */
	hash[SNEFRU_INPUT_BLOCK_SIZE - 2] = bitCount[0];/* upper 32 bits of
							 * count */
	hash[SNEFRU_INPUT_BLOCK_SIZE - 1] = bitCount[1];/* lower 32 bits of
							 * count */
	/* Final hash down.  */
	Snefru512 (hashValue, hashValueSize,
			hash, SNEFRU_INPUT_BLOCK_SIZE, securityLevel);
}

