#include <json/rapidjson.h>
#include <json/stringbuffer.h>
#include <json/writer.h>
#include <encode/aes.h>
#include "RemoteSave.h"

#ifdef _MSC_VER
#ifndef  __PRETTY_FUNCTION__
#define __PRETTY_FUNCTION__ __FUNCTION__
#endif
#endif

namespace __RemoveSave_private
{
#define CBC 1
	/*

	This is an implementation of the AES128 algorithm, specifically ECB and CBC mode.

	The implementation is verified against the test vectors in:
	National Institute of Standards and Technology Special Publication 800-38A 2001 ED

	ECB-AES128
	----------

	plain-text:
	6bc1bee22e409f96e93d7e117393172a
	ae2d8a571e03ac9c9eb76fac45af8e51
	30c81c46a35ce411e5fbc1191a0a52ef
	f69f2445df4f9b17ad2b417be66c3710

	key:
	2b7e151628aed2a6abf7158809cf4f3c

	resulting cipher
	3ad77bb40d7a3660a89ecaf32466ef97
	f5d3d58503b9699de785895a96fdbaaf
	43b1cd7f598ece23881b00e3ed030688
	7b0c785e27e8ad3f8223207104725dd4


	NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
	You should pad the end of the string with zeros if this is not the case.

	*/


	/*****************************************************************************/
	/* Includes:                                                                 */
	/*****************************************************************************/
// #include <stdint.h>
// #include <string.h> // CBC mode, for memset
// #include "aes.h"


	/*****************************************************************************/
	/* Defines:                                                                  */
	/*****************************************************************************/
	// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
	// The number of 32 bit words in a key.
#define Nk 4
	// Key length in bytes [128 bit]
#define KEYLEN 16
	// The number of rounds in AES Cipher.
#define Nr 10

	// jcallan@github points out that declaring Multiply as a function 
	// reduces code size considerably with the Keil ARM compiler.
	// See this link for more information: https://github.com/kokke/tiny-AES128-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
#define MULTIPLY_AS_A_FUNCTION 0
#endif


	/*****************************************************************************/
	/* Private variables:                                                        */
	/*****************************************************************************/
	// state - array holding the intermediate results during decryption.
	typedef uint8_t state_t[4][4];
	static state_t* state;

	// The array that stores the round keys.
	static uint8_t RoundKey[176];

	// The Key input to the AES Program
	static const uint8_t* Key;

#if defined(CBC) && CBC
	// Initial Vector used only for CBC mode
	static const uint8_t* Iv;
#endif

	// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
	// The numbers below can be computed dynamically trading ROM for RAM - 
	// This can be useful in (embedded) bootloader applications, where ROM is often limited.
	static const uint8_t sbox[256] = {
		//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

	static const uint8_t rsbox[256] =
	{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };


	// The round constant word array, Rcon[i], contains the values given by 
	// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
	// Note that i starts at 1, not 0).
	static const uint8_t Rcon[255] = {
		0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
		0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
		0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
		0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
		0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
		0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
		0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
		0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
		0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
		0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
		0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
		0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
		0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
		0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
		0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
		0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };


	/*****************************************************************************/
	/* Private functions:                                                        */
	/*****************************************************************************/
	static uint8_t getSBoxValue(uint8_t num)
	{
		return sbox[num];
	}

	static uint8_t getSBoxInvert(uint8_t num)
	{
		return rsbox[num];
	}

	// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
	static void KeyExpansion(void)
	{
		uint32_t i, j, k;
		uint8_t tempa[4]; // Used for the column/row operations

		// The first round key is the key itself.
		for (i = 0; i < Nk; ++i)
		{
			RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
			RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
			RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
			RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
		}

		// All other round keys are found from the previous round keys.
		for (; (i < (Nb * (Nr + 1))); ++i)
		{
			for (j = 0; j < 4; ++j)
			{
				tempa[j] = RoundKey[(i - 1) * 4 + j];
			}
			if (i % Nk == 0)
			{
				// This function rotates the 4 bytes in a word to the left once.
				// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

				// Function RotWord()
				{
					k = tempa[0];
					tempa[0] = tempa[1];
					tempa[1] = tempa[2];
					tempa[2] = tempa[3];
					tempa[3] = k;
				}

				// SubWord() is a function that takes a four-byte input word and 
				// applies the S-box to each of the four bytes to produce an output word.

				// Function Subword()
	  {
		  tempa[0] = getSBoxValue(tempa[0]);
		  tempa[1] = getSBoxValue(tempa[1]);
		  tempa[2] = getSBoxValue(tempa[2]);
		  tempa[3] = getSBoxValue(tempa[3]);
	  }

	  tempa[0] = tempa[0] ^ Rcon[i / Nk];
			}
			else if (Nk > 6 && i % Nk == 4)
			{
				// Function Subword()
				{
					tempa[0] = getSBoxValue(tempa[0]);
					tempa[1] = getSBoxValue(tempa[1]);
					tempa[2] = getSBoxValue(tempa[2]);
					tempa[3] = getSBoxValue(tempa[3]);
				}
			}
			RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ tempa[0];
			RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ tempa[1];
			RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ tempa[2];
			RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ tempa[3];
		}
	}

	// This function adds the round key to state.
	// The round key is added to the state by an XOR function.
	static void AddRoundKey(uint8_t round)
	{
		uint8_t i, j;
		for (i = 0; i < 4; ++i)
		{
			for (j = 0; j < 4; ++j)
			{
				(*state)[i][j] ^= RoundKey[round * Nb * 4 + i * Nb + j];
			}
		}
	}

	// The SubBytes Function Substitutes the values in the
	// state matrix with values in an S-box.
	static void SubBytes(void)
	{
		uint8_t i, j;
		for (i = 0; i < 4; ++i)
		{
			for (j = 0; j < 4; ++j)
			{
				(*state)[j][i] = getSBoxValue((*state)[j][i]);
			}
		}
	}

	// The ShiftRows() function shifts the rows in the state to the left.
	// Each row is shifted with different offset.
	// Offset = Row number. So the first row is not shifted.
	static void ShiftRows(void)
	{
		uint8_t temp;

		// Rotate first row 1 columns to left  
		temp = (*state)[0][1];
		(*state)[0][1] = (*state)[1][1];
		(*state)[1][1] = (*state)[2][1];
		(*state)[2][1] = (*state)[3][1];
		(*state)[3][1] = temp;

		// Rotate second row 2 columns to left  
		temp = (*state)[0][2];
		(*state)[0][2] = (*state)[2][2];
		(*state)[2][2] = temp;

		temp = (*state)[1][2];
		(*state)[1][2] = (*state)[3][2];
		(*state)[3][2] = temp;

		// Rotate third row 3 columns to left
		temp = (*state)[0][3];
		(*state)[0][3] = (*state)[3][3];
		(*state)[3][3] = (*state)[2][3];
		(*state)[2][3] = (*state)[1][3];
		(*state)[1][3] = temp;
	}

	static uint8_t xtime(uint8_t x)
	{
		return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
	}

	// MixColumns function mixes the columns of the state matrix
	static void MixColumns(void)
	{
		uint8_t i;
		uint8_t Tmp, Tm, t;
		for (i = 0; i < 4; ++i)
		{
			t = (*state)[i][0];
			Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
			Tm = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp;
			Tm = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp;
			Tm = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp;
			Tm = (*state)[i][3] ^ t;        Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp;
		}
	}

	// Multiply is used to multiply numbers in the field GF(2^8)
#if MULTIPLY_AS_A_FUNCTION
	static uint8_t Multiply(uint8_t x, uint8_t y)
	{
		return (((y & 1) * x) ^
				((y >> 1 & 1) * xtime(x)) ^
				((y >> 2 & 1) * xtime(xtime(x))) ^
				((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
				((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
	}
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

	// MixColumns function mixes the columns of the state matrix.
	// The method used to multiply may be difficult to understand for the inexperienced.
	// Please use the references to gain more information.
	static void InvMixColumns(void)
	{
		int i;
		uint8_t a, b, c, d;
		for (i = 0; i < 4; ++i)
		{
			a = (*state)[i][0];
			b = (*state)[i][1];
			c = (*state)[i][2];
			d = (*state)[i][3];

			(*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
			(*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
			(*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
			(*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
		}
	}


	// The SubBytes Function Substitutes the values in the
	// state matrix with values in an S-box.
	static void InvSubBytes(void)
	{
		uint8_t i, j;
		for (i = 0; i < 4; ++i)
		{
			for (j = 0; j < 4; ++j)
			{
				(*state)[j][i] = getSBoxInvert((*state)[j][i]);
			}
		}
	}

	static void InvShiftRows(void)
	{
		uint8_t temp;

		// Rotate first row 1 columns to right  
		temp = (*state)[3][1];
		(*state)[3][1] = (*state)[2][1];
		(*state)[2][1] = (*state)[1][1];
		(*state)[1][1] = (*state)[0][1];
		(*state)[0][1] = temp;

		// Rotate second row 2 columns to right 
		temp = (*state)[0][2];
		(*state)[0][2] = (*state)[2][2];
		(*state)[2][2] = temp;

		temp = (*state)[1][2];
		(*state)[1][2] = (*state)[3][2];
		(*state)[3][2] = temp;

		// Rotate third row 3 columns to right
		temp = (*state)[0][3];
		(*state)[0][3] = (*state)[1][3];
		(*state)[1][3] = (*state)[2][3];
		(*state)[2][3] = (*state)[3][3];
		(*state)[3][3] = temp;
	}


	// Cipher is the main function that encrypts the PlainText.
	static void Cipher(void)
	{
		uint8_t round = 0;

		// Add the First round key to the state before starting the rounds.
		AddRoundKey(0);

		// There will be Nr rounds.
		// The first Nr-1 rounds are identical.
		// These Nr-1 rounds are executed in the loop below.
		for (round = 1; round < Nr; ++round)
		{
			SubBytes();
			ShiftRows();
			MixColumns();
			AddRoundKey(round);
		}

		// The last round is given below.
		// The MixColumns function is not here in the last round.
		SubBytes();
		ShiftRows();
		AddRoundKey(Nr);
	}

	static void InvCipher(void)
	{
		uint8_t round = 0;

		// Add the First round key to the state before starting the rounds.
		AddRoundKey(Nr);

		// There will be Nr rounds.
		// The first Nr-1 rounds are identical.
		// These Nr-1 rounds are executed in the loop below.
		for (round = Nr - 1; round > 0; round--)
		{
			InvShiftRows();
			InvSubBytes();
			AddRoundKey(round);
			InvMixColumns();
		}

		// The last round is given below.
		// The MixColumns function is not here in the last round.
		InvShiftRows();
		InvSubBytes();
		AddRoundKey(0);
	}

	static void BlockCopy(uint8_t* output, const uint8_t* input)
	{
		uint8_t i;
		for (i = 0; i < KEYLEN; ++i)
		{
			output[i] = input[i];
		}
	}



	/*****************************************************************************/
	/* Public functions:                                                         */
	/*****************************************************************************/
#if defined(ECB) && ECB
	
	void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t* output)
	{
		// Copy input to output, and work in-memory on output
		BlockCopy(output, input);
		state = (state_t*)output;

		Key = key;
		KeyExpansion();

		// The next function call encrypts the PlainText with the Key using AES algorithm.
		Cipher();
	}

	void AES128_ECB_decrypt(uint8_t* input, const uint8_t* key, uint8_t *output)
	{
		// Copy input to output, and work in-memory on output
		BlockCopy(output, input);
		state = (state_t*)output;

		// The KeyExpansion routine must be called before encryption.
		Key = key;
		KeyExpansion();

		InvCipher();
	}

#endif // #if defined(ECB) && ECB


#if defined(CBC) && CBC
	
	static void XorWithIv(uint8_t* buf)
	{
		uint8_t i;
		for (i = 0; i < KEYLEN; ++i)
		{
			buf[i] ^= Iv[i];
		}
	}

	void AES128_CBC_encrypt_buffer(uint8_t* output, const uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
	{
		uintptr_t i;
		uint8_t remainders = length % KEYLEN; /* Remaining bytes in the last non-full block */

		// 	BlockCopy(output, input);
		// 	state = (state_t*)output;

		// Skip the key expansion if key is passed as 0
		if (0 != key)
		{
			Key = key;
			KeyExpansion();
		}

		if (iv != 0)
		{
			Iv = (uint8_t*)iv;
		}

		for (i = KEYLEN; i <= length; i += KEYLEN)
		{
			BlockCopy(output, input);
			XorWithIv(output);
			state = (state_t*)output;
			Cipher();
			Iv = output;
			input += KEYLEN;
			output += KEYLEN;
		}

		if (remainders)
		{
			memcpy(output, input, remainders);
			memset(output + remainders, 0, KEYLEN - remainders); /* add 0-padding */
			XorWithIv(output);
			state = (state_t*)output;
			Cipher();
		}
	}

	void AES128_CBC_decrypt_buffer(uint8_t* output, const uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
	{
		uintptr_t i;
		uint8_t remainders = length % KEYLEN; /* Remaining bytes in the last non-full block */

		// 	BlockCopy(output, input);
		// 	state = (state_t*)output;

		// Skip the key expansion if key is passed as 0
		if (0 != key)
		{
			Key = key;
			KeyExpansion();
		}

		// If iv is passed as 0, we continue to encrypt without re-setting the Iv
		if (iv != 0)
		{
			Iv = (uint8_t*)iv;
		}

		for (i = KEYLEN; i <= length; i += KEYLEN)
		{
			BlockCopy(output, input);
			state = (state_t*)output;
			InvCipher();
			XorWithIv(output);
			Iv = input;
			input += KEYLEN;
			output += KEYLEN;
		}

		if (remainders)
		{
			BlockCopy(output, input);
			state = (state_t*)output;
			InvCipher();
			XorWithIv(output);
			memset(output + remainders, 0, KEYLEN - remainders); /* add 0-padding */
		}
	}
	
#endif // #if defined(CBC) && CBC
} // namespace


const std::string RemoteSave::NullString = "";
RemoteSave* RemoteSave::m_instance = nullptr;

RemoteSave::RemoteSave() 
	: m_inited(false)
	, m_saveOnGetDefault(false)
	, m_saveOnChangeValue(false)
	, m_cbOnLoad(nullptr)
	, m_cbOnSave(nullptr)
	, m_sn(0)
{
}

bool RemoteSave::getBoolForKey(const char *pKey, bool defaultValue /* = false */)
{
	if (!m_inited)
	{
		return defaultValue;
	}

	if (!pKey || !(*pKey))
	{
		return defaultValue;
	}

	auto it = m_jsonDoc.FindMember(pKey);
	if (it != m_jsonDoc.MemberEnd())
	{
		auto &node = it->value;
		if (node.IsBool())
		{
			return node.GetBool();
		}
	}

	rapidjson::Value jsonValue(defaultValue);
	rapidjson::Document::AllocatorType &allocator = m_jsonDoc.GetAllocator();
	m_jsonDoc.RemoveMember(pKey);
	m_jsonDoc.AddMember(rapidjson::Value(pKey, allocator).Move(), jsonValue, allocator);
	saveOnGetDefault();

	return defaultValue;
}

int RemoteSave::getIntegerForKey(const char *pKey, int defaultValue /* = 0 */)
{
	if (!m_inited)
	{
		return defaultValue;
	}

	if (!pKey || !(*pKey))
	{
		return defaultValue;
	}

	auto it = m_jsonDoc.FindMember(pKey);
	if (it != m_jsonDoc.MemberEnd())
	{
		auto &node = it->value;
		if (node.IsInt())
		{
			return node.GetInt();
		}
	}

	rapidjson::Value jsonValue(defaultValue);
	rapidjson::Document::AllocatorType &allocator = m_jsonDoc.GetAllocator();
	m_jsonDoc.RemoveMember(pKey);
	m_jsonDoc.AddMember(rapidjson::Value(pKey, allocator).Move(), jsonValue, allocator);
	saveOnGetDefault();

	return defaultValue;
}

float RemoteSave::getFloatForKey(const char *pKey, float defaultValue /* = 0.f */)
{
	if (!m_inited)
	{
		return defaultValue;
	}

	if (!pKey || !(*pKey))
	{
		return defaultValue;
	}

	auto it = m_jsonDoc.FindMember(pKey);
	if (it != m_jsonDoc.MemberEnd())
	{
		auto &node = it->value;
		if (node.IsDouble())
		{
			return node.GetDouble();
		}
	}

	rapidjson::Value jsonValue(defaultValue);
	rapidjson::Document::AllocatorType &allocator = m_jsonDoc.GetAllocator();
	m_jsonDoc.RemoveMember(pKey);
	m_jsonDoc.AddMember(rapidjson::Value(pKey, allocator).Move(), jsonValue, allocator);
	saveOnGetDefault();

	return defaultValue;
}

double RemoteSave::getDoubleForKey(const char *pKey, double defaultValue /* = 0. */)
{
	if (!m_inited)
	{
		return defaultValue;
	}

	if (!pKey || !(*pKey))
	{
		return defaultValue;
	}

	auto it = m_jsonDoc.FindMember(pKey);
	if (it != m_jsonDoc.MemberEnd())
	{
		auto &node = it->value;
		if (node.IsDouble())
		{
			return node.GetDouble();
		}
	}

	rapidjson::Value jsonValue(defaultValue);
	rapidjson::Document::AllocatorType &allocator = m_jsonDoc.GetAllocator();
	m_jsonDoc.RemoveMember(pKey);
	m_jsonDoc.AddMember(rapidjson::Value(pKey, allocator).Move(), jsonValue, allocator);
	saveOnGetDefault();

	return defaultValue;
}

std::string RemoteSave::getStringForKey(const char *pKey, const std::string &defaultValue /* = RemoteSave::NullString */)
{
	if (!m_inited)
	{
		return defaultValue;
	}

	if (!pKey || !(*pKey))
	{
		return defaultValue;
	}

	auto it = m_jsonDoc.FindMember(pKey);
	if (it != m_jsonDoc.MemberEnd())
	{
		auto &node = it->value;
		if (node.IsString())
		{
			auto str = node.GetString();
			auto len = node.GetStringLength();
			std::string ret(str, len);
			return ret;
		}
	}

	rapidjson::Document::AllocatorType &allocator = m_jsonDoc.GetAllocator();

	rapidjson::Value jsonValue;
	jsonValue.SetString(defaultValue.c_str(), defaultValue.size(), allocator);

	m_jsonDoc.RemoveMember(pKey);
	m_jsonDoc.AddMember(rapidjson::Value(pKey, allocator).Move(), jsonValue, allocator);
	saveOnGetDefault();

	return defaultValue;
}

cocos2d::Data RemoteSave::getDataForKey(const char *pKey, const cocos2d::Data &defaultValue /* = cocos2d::Data::Null */)
{
	if (!m_inited)
	{
		return defaultValue;
	}

	if (!pKey || !(*pKey))
	{
		return defaultValue;
	}

	auto it = m_jsonDoc.FindMember(pKey);
	if (it != m_jsonDoc.MemberEnd())
	{
		auto &node = it->value;
		if (node.IsString())
		{
			auto str = node.GetString();
			auto len = node.GetStringLength();

			unsigned char *decodedData = nullptr;
			auto decodedDataLen = cocos2d::base64Decode((const unsigned char *)str, len, &decodedData);
			if (decodedData)
			{
				cocos2d::Data ret;
				ret.fastSet(decodedData, decodedDataLen);
				return ret;
			}
		}
	}

	char *encodedData = nullptr;
	auto encodedDataLen = cocos2d::base64Encode(defaultValue.getBytes(), defaultValue.getSize(), &encodedData);
	if (!encodedData)
	{
		CCLOG("[%s]: base64Encode() failed", __PRETTY_FUNCTION__);
	}
	else
	{
		rapidjson::Document::AllocatorType &allocator = m_jsonDoc.GetAllocator();

		rapidjson::Value jsonValue;
		jsonValue.SetString(encodedData, encodedDataLen, allocator);

		m_jsonDoc.RemoveMember(pKey);
		m_jsonDoc.AddMember(rapidjson::Value(pKey, allocator).Move(), jsonValue, allocator);
		saveOnGetDefault();

		free(encodedData); encodedData = nullptr;
	}

	return defaultValue;
}

void RemoteSave::setBoolForKey(const char *pKey, bool value)
{
	if (!m_inited)
	{
		return;
	}

	if (!pKey || !(*pKey))
	{
		return;
	}

	auto it = m_jsonDoc.FindMember(pKey);
	if (it != m_jsonDoc.MemberEnd())
	{
		auto &node = it->value;
		if (node.IsBool())
		{
			auto curValue = node.GetBool();
			if (curValue == value)
			{
				return;
			}
		}
	}

	rapidjson::Value jsonValue(value);
	rapidjson::Document::AllocatorType &allocator = m_jsonDoc.GetAllocator();
	m_jsonDoc.RemoveMember(pKey);
	m_jsonDoc.AddMember(rapidjson::Value(pKey, allocator).Move(), jsonValue, allocator);
	saveOnChangeValue();
}

void RemoteSave::setIntegerForKey(const char *pKey, int value)
{
	if (!m_inited)
	{
		return;
	}

	if (!pKey || !(*pKey))
	{
		return;
	}

	auto it = m_jsonDoc.FindMember(pKey);
	if (it != m_jsonDoc.MemberEnd())
	{
		auto &node = it->value;
		if (node.IsInt())
		{
			auto curValue = node.GetInt();
			if (curValue == value)
			{
				return;
			}
		}
	}

	rapidjson::Value jsonValue(value);
	rapidjson::Document::AllocatorType &allocator = m_jsonDoc.GetAllocator();
	m_jsonDoc.RemoveMember(pKey);
	m_jsonDoc.AddMember(rapidjson::Value(pKey, allocator).Move(), jsonValue, allocator);
	saveOnChangeValue();
}

void RemoteSave::setFloatForKey(const char *pKey, float value)
{
	if (!m_inited)
	{
		return;
	}

	if (!pKey || !(*pKey))
	{
		return;
	}

	auto it = m_jsonDoc.FindMember(pKey);
	if (it != m_jsonDoc.MemberEnd())
	{
		auto &node = it->value;
		if (node.IsDouble())
		{
			auto curValue = node.GetDouble();
			if (curValue == value)
			{
				return;
			}
		}
	}

	rapidjson::Value jsonValue(value);
	rapidjson::Document::AllocatorType &allocator = m_jsonDoc.GetAllocator();
	m_jsonDoc.RemoveMember(pKey);
	m_jsonDoc.AddMember(rapidjson::Value(pKey, allocator).Move(), jsonValue, allocator);
	saveOnChangeValue();
}

void RemoteSave::setDoubleForKey(const char *pKey, double value)
{
	if (!m_inited)
	{
		return;
	}

	if (!pKey || !(*pKey))
	{
		return;
	}

	auto it = m_jsonDoc.FindMember(pKey);
	if (it != m_jsonDoc.MemberEnd())
	{
		auto &node = it->value;
		if (node.IsDouble())
		{
			auto curValue = node.GetDouble();
			if (curValue == value)
			{
				return;
			}
		}
	}

	rapidjson::Value jsonValue(value);
	rapidjson::Document::AllocatorType &allocator = m_jsonDoc.GetAllocator();
	m_jsonDoc.RemoveMember(pKey);
	m_jsonDoc.AddMember(rapidjson::Value(pKey, allocator).Move(), jsonValue, allocator);
	saveOnChangeValue();
}

void RemoteSave::setStringForKey(const char *pKey, const std::string &value)
{
	if (!m_inited)
	{
		return;
	}

	if (!pKey || !(*pKey))
	{
		return;
	}

	auto it = m_jsonDoc.FindMember(pKey);
	if (it != m_jsonDoc.MemberEnd())
	{
		auto &node = it->value;
		if (node.IsString())
		{
			auto str = node.GetString();
			auto len = node.GetStringLength();
			std::string curValue(str, len);
			if (curValue == value)
			{
				return;
			}
		}
	}

	rapidjson::Document::AllocatorType &allocator = m_jsonDoc.GetAllocator();

	rapidjson::Value jsonValue;
	jsonValue.SetString(value.data(), value.size(), allocator);

	m_jsonDoc.RemoveMember(pKey);
	m_jsonDoc.AddMember(rapidjson::Value(pKey, allocator).Move(), jsonValue, allocator);
	saveOnChangeValue();
}

void RemoteSave::setDataForKey(const char *pKey, const cocos2d::Data &value)
{
	if (!m_inited)
	{
		return;
	}

	if (!pKey || !(*pKey))
	{
		return;
	}

	auto valueBuffer = value.getBytes();
	auto valueSize = value.getSize();

	auto it = m_jsonDoc.FindMember(pKey);
	if (it != m_jsonDoc.MemberEnd())
	{
		auto &node = it->value;
		if (node.IsString())
		{
			auto str = node.GetString();
			auto len = node.GetStringLength();

			unsigned char *decodedData = nullptr;
			auto decodedDataLen = cocos2d::base64Decode((const unsigned char *)str, len, &decodedData);
			if (decodedData)
			{
				if (decodedDataLen == valueSize)
				{
					if (memcmp(valueBuffer, decodedData, valueSize) == 0)
					{
						return;
					}
				}
				free(decodedData); decodedData = nullptr;
			}
		}
	}

	char *encodedData = nullptr;
	auto encodedDataLen = cocos2d::base64Encode(valueBuffer, valueSize, &encodedData);
	if (!encodedData)
	{
		CCLOG("[%s]: base64Encode() failed", __PRETTY_FUNCTION__);
	}
	else
	{
		rapidjson::Document::AllocatorType &allocator = m_jsonDoc.GetAllocator();

		rapidjson::Value jsonValue;
		jsonValue.SetString(encodedData, encodedDataLen, allocator);

		m_jsonDoc.RemoveMember(pKey);
		m_jsonDoc.AddMember(rapidjson::Value(pKey, allocator).Move(), jsonValue, allocator);
		saveOnChangeValue();

		free(encodedData); encodedData = nullptr;
	}
}

bool RemoteSave::init(const std::string &uid, const std::string &version,
					  const std::string &key, const std::string &iv, 
					  const std::string &urlLoad, const std::string &urlSave)
{
	if (m_inited)
	{
		cocos2d::log("[%s]: already inited", __PRETTY_FUNCTION__);
		return false;
	}

	if (uid.empty())
	{
		cocos2d::log("[%s]: empty uid", __PRETTY_FUNCTION__);
		return false;
	}

	if (version.empty())
	{
		cocos2d::log("[%s]: empty version", __PRETTY_FUNCTION__);
		return false;
	}

	if (key.size() < 16)
	{
		cocos2d::log("[%s]: invalid key: %s", __PRETTY_FUNCTION__, key.c_str());
		return false;
	}

	if (iv.size() < 16)
	{
		cocos2d::log("[%s]: invalid iv: %s", __PRETTY_FUNCTION__, iv.c_str());
		return false;
	}

	m_uid = uid;
	m_version = version;
	m_key = key;
	m_iv = iv;
	m_urlLoad = urlLoad;
	m_urlSave = urlSave;

	m_sn = 0;
	m_jsonDoc.SetNull();
	m_inited = true;

	return true;
}

void RemoteSave::release()
{
    if (!m_inited)
    {
        return;
    }
    
    m_inited = false;
    m_sn = 0;
    m_jsonDoc.SetObject();
}

void RemoteSave::load()
{
	if (!m_inited)
	{
		return;
	}

	sendRequestLoadGame();
}

void RemoteSave::save()
{
	if (!m_inited)
	{
		return;
	}

	sendRequestSaveGame();
}

void RemoteSave::sendRequestLoadGame()
{
	cocos2d::network::HttpRequest* request = new (std::nothrow) cocos2d::network::HttpRequest();
	request->setUrl(m_urlLoad.c_str());
	request->setRequestType(cocos2d::network::HttpRequest::Type::POST);
	request->setResponseCallback(CC_CALLBACK_2(RemoteSave::onHttpRequestCompletedLoadGame, this));

	std::string uid;
	encode(m_uid, uid);

	auto postDataIn = "user_id=" + uid;
	std::string postDataOut;
	formatPostData(postDataIn, postDataOut);

	request->setRequestData(postDataOut.c_str(), postDataOut.length());
	cocos2d::log("[%s]: Post request, url: %s, data: %s", __PRETTY_FUNCTION__, m_urlLoad.c_str(), postDataOut.c_str());

	auto tag = "POST load data for uid: " + m_uid;
	request->setTag(tag.c_str());
	cocos2d::network::HttpClient::getInstance()->sendImmediate(request);
	request->release();
}

void RemoteSave::onHttpRequestCompletedLoadGame(cocos2d::network::HttpClient *sender, cocos2d::network::HttpResponse *response)
{
	if (!response)
	{
		return;
	}

	// You can get original request type from: response->request->reqType
	auto tag = response->getHttpRequest()->getTag();
	if (tag)
	{
		cocos2d::log("[%s]: Receive response: %s", __PRETTY_FUNCTION__, tag);
	}

	auto statusCode = response->getResponseCode();
	cocos2d::log("[%s]: HTTP Status Code: %ld", __PRETTY_FUNCTION__, statusCode);

	ErrorCode code = EC_OK;
	std::string msg;
	do 
	{
		if (!response->isSucceed())
		{
			code = EC_RESPONSE;
			msg = response->getErrorBuffer();
			cocos2d::log("[%s]: Response failed, error: %s", __PRETTY_FUNCTION__, msg.c_str());
			break;
		}

		auto buffer = response->getResponseData();
		auto text = std::string(buffer->begin(), buffer->end());
		cocos2d::log("[%s]: Response succeeded, buffer: %s", __PRETTY_FUNCTION__, text.c_str());

		unsigned long long sn = 0;
		std::string saveData;
		if (!parseResponseLoadGame(text, sn, saveData))
		{
			code = EC_PARSE_RESPONSE;
			msg = "";
			cocos2d::log("[%s]: parseResponseLoadGame failed", __PRETTY_FUNCTION__);
			break;
		}

		if (!loadWithBuffer(saveData))
		{
			code = EC_LOAD_DATA;
			msg = "";
			cocos2d::log("[%s]: loadWithBuffer failed", __PRETTY_FUNCTION__);
			break;
		}

		m_sn = sn;
	} while (0);

	if (m_cbOnLoad)
	{
		m_cbOnLoad(code, msg);
	}
}

bool RemoteSave::parseResponseLoadGame(const std::string &buffer, unsigned long long &sn, std::string &saveData)
{
	if (buffer.empty())
	{
		cocos2d::log("[%s]: buffer empty", __PRETTY_FUNCTION__);
		return false;
	}

	saveData = "";
	sn = 0;
	if (buffer != "NULL")
	{
		rapidjson::Document jsonDoc;
		jsonDoc.Parse(buffer.c_str());
		if (jsonDoc.HasParseError())  //打印解析错误
		{
			cocos2d::log("[%s]: jsonDoc.Parse() failed, Error: %d", __PRETTY_FUNCTION__,
						 jsonDoc.GetParseError());
			return false;
		}

		if (!jsonDoc.IsObject())
		{
			cocos2d::log("[%s]: jsonDoc is not an object", __PRETTY_FUNCTION__);
			return false;
		}

		auto itSN = jsonDoc.FindMember("sn");
		if (itSN != jsonDoc.MemberEnd())
		{
			auto &node = itSN->value;
			if (node.IsUint64())
			{
				sn = node.GetUint64();
			}
		}

		auto itSaveData = jsonDoc.FindMember("save_data");
		if (itSaveData != jsonDoc.MemberEnd())
		{
			auto &node = itSaveData->value;
			if (node.IsString())
			{
				auto str = node.GetString();
				auto len = node.GetStringLength();
				std::string saveDataEncode(str, len);
				decode(saveDataEncode, saveData);
			}
		}
	}

	cocos2d::log("[%s]: game loaded, sn: %s, save_data: %s", __PRETTY_FUNCTION__,
				 std::to_string(sn).c_str(), saveData.c_str());
	return true;
}

bool RemoteSave::loadWithBuffer(const std::string &buffer)
{
	if (buffer.empty())
	{
		cocos2d::log("[%s]: empty JSON buffer", __PRETTY_FUNCTION__);
		m_jsonDoc.SetObject();
		return true;
	}

	m_jsonDoc.Parse(buffer.c_str());
	if (m_jsonDoc.HasParseError())
	{
		cocos2d::log("[%s]: m_jsonDoc.Parse() failed, Error: %d", __PRETTY_FUNCTION__,
					 m_jsonDoc.GetParseError());
		return false;
	}

	if (!m_jsonDoc.IsObject())
	{
		cocos2d::log("[%s]: m_jsonDoc is not an object", __PRETTY_FUNCTION__);
		return false;
	}

	return true;
}

void RemoteSave::sendRequestSaveGame()
{
	std::string buffer;
	if (!saveToBuffer(buffer))
	{
		if (m_cbOnSave)
		{
			m_cbOnSave(EC_SAVE_DATA, NullString);
		}
		cocos2d::log("[%s]: saveToBuffer failed", __PRETTY_FUNCTION__);
		return;
	}

	cocos2d::log("[%s]: save game: %s", __PRETTY_FUNCTION__, buffer.c_str());

	cocos2d::network::HttpRequest* request = new (std::nothrow) cocos2d::network::HttpRequest();
	request->setUrl(m_urlSave.c_str());
	request->setRequestType(cocos2d::network::HttpRequest::Type::POST);
	request->setResponseCallback(CC_CALLBACK_2(RemoteSave::onHttpRequestCompletedSaveGame, this));

	std::string uid;
	encode(m_uid, uid);
	++m_sn;

	std::string saveData;
	encode(buffer, saveData);

	// write the post data
	auto postDataIn = "user_id=" + uid
		+ "&sn=" + std::to_string(m_sn)
		+ "&version=" + m_version
		+ "&save_data=" + saveData;
	std::string postDatOut;
	formatPostData(postDataIn, postDatOut);
	request->setRequestData(postDatOut.c_str(), postDatOut.length());
	cocos2d::log("[%s]: Post request, url: %s, data: %s", __PRETTY_FUNCTION__, m_urlSave.c_str(), postDatOut.c_str());

	auto tag = "POST save data for uid: " + m_uid;
	request->setTag(tag.c_str());
	cocos2d::network::HttpClient::getInstance()->sendImmediate(request);
	request->release();
}

void RemoteSave::onHttpRequestCompletedSaveGame(cocos2d::network::HttpClient *sender, cocos2d::network::HttpResponse *response)
{
	if (!response)
	{
		return;
	}

	// You can get original request type from: response->request->reqType
	auto tag = response->getHttpRequest()->getTag();
	if (tag)
	{
		cocos2d::log("[%s]: Receive response: %s", __PRETTY_FUNCTION__, tag);
	}

	auto statusCode = response->getResponseCode();
	cocos2d::log("[%s]: HTTP Status Code: %ld", __PRETTY_FUNCTION__, statusCode);

	ErrorCode code = EC_OK;
	std::string msg;
	do 
	{
		if (!response->isSucceed())
		{
			code = EC_RESPONSE;
			msg = response->getErrorBuffer();
			cocos2d::log("[%s]: Response failed, error: %s", __PRETTY_FUNCTION__, msg.c_str());
			break;
		}

		auto buffer = response->getResponseData();
		auto text = std::string(buffer->begin(), buffer->end());
		cocos2d::log("[%s]: Response succeeded, buffer: %s", __PRETTY_FUNCTION__, text.c_str());

		if (text != "Done")
		{
			code = EC_SAVE_RESULT;
			msg = text;
			cocos2d::log("[%s]: save failed, %s", __PRETTY_FUNCTION__, msg.c_str());
		}
	} while (0);

	if (m_cbOnSave)
	{
		m_cbOnSave(code, msg);
	}
}

bool RemoteSave::saveToBuffer(std::string &buffer)
{
	if (!m_jsonDoc.IsObject())
	{
		cocos2d::log("[%s]: m_jsonDoc is NOT a json obj", __PRETTY_FUNCTION__);
		buffer = "";
		return false;
	}

	rapidjson::StringBuffer jsonBuffer;
	rapidjson::Writer<rapidjson::StringBuffer> jsonWriter(jsonBuffer);
	if (!m_jsonDoc.Accept(jsonWriter))
	{
		cocos2d::log("[%s]: m_jsonDoc.Accept() failed", __PRETTY_FUNCTION__);
		buffer = "";
		return false;
	}

	auto str = jsonBuffer.GetString();
	auto size = jsonBuffer.GetSize();
	buffer.assign(static_cast<const char*>(str), size);
	return true;
}

void RemoteSave::encode(const std::string &in, std::string &out)
{
	auto bufferIn = (unsigned char*)in.c_str();
	auto sizeIn = in.size();
	auto key = (unsigned char*)m_key.c_str();
	auto iv = (unsigned char*)m_iv.c_str();
	auto sizeAES = sizeIn;
	auto k = sizeIn % 16; // 128 bit
	if (k)
	{
		sizeAES = sizeIn - k + 16;
	}
	auto bufferAESOut = new unsigned char[sizeAES];
	__RemoveSave_private::AES128_CBC_encrypt_buffer(bufferAESOut, bufferIn, sizeIn, key, iv);

	char *bufferOut = nullptr;
	auto sizeOut = cocos2d::base64Encode(bufferAESOut, sizeAES, &bufferOut);
	out.assign(bufferOut, sizeOut);

	free(bufferOut); bufferOut = nullptr;
	delete[] bufferAESOut; bufferAESOut = nullptr;
}

void RemoteSave::decode(const std::string &in, std::string &out)
{
	auto bufferIn = (unsigned char*)in.c_str();
	auto sizeIn = in.size();
	unsigned char *bufferOut = nullptr;
	auto sizeOut = cocos2d::base64Decode(bufferIn, sizeIn, &bufferOut);

	auto key = (unsigned char*)m_key.c_str();
	auto iv = (unsigned char*)m_iv.c_str();

	// 2015/12/10-18:06 by YYBear [TODO] 这里的实际解密后的Size实际上是错误的，尾部可能会有填充的0，但是由于这里最后解密出来的应该是个json字符串，所以尾部的0不会产生影响
	auto bufferAESOut = new unsigned char[sizeOut];
	__RemoveSave_private::AES128_CBC_decrypt_buffer(bufferAESOut, bufferOut, sizeOut, key, iv);
	out.assign((char *)bufferAESOut, sizeOut);

	free(bufferOut); bufferOut = nullptr;
	delete[] bufferAESOut; bufferAESOut = nullptr;
}


void RemoteSave::formatPostData(const std::string &dataIn, std::string &dataOut)
{
	std::string c = "+";
	std::string t = "%2B";
	std::string::size_type pos1, pos2;
	pos1 = 0;
	pos2 = dataIn.find('+');

	while (std::string::npos != pos2)
	{
		dataOut += dataIn.substr(pos1, pos2 - pos1);
		dataOut += t;

		pos1 = pos2 + c.size();
		pos2 = dataIn.find(c, pos1);
	}

	if (pos1 != dataIn.length())
	{
		dataOut += dataIn.substr(pos1);
	}
}
