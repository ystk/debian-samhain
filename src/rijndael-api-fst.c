/*
 * rijndael-api-fst.c   v2.3   April '2000
 *
 * Optimised ANSI C code
 *
 * authors: v1.0: Antoon Bosselaers
 *          v2.0: Vincent Rijmen
 *          v2.1: Vincent Rijmen
 *          v2.2: Vincent Rijmen
 *          v2.3: Paulo Barreto
 *          v2.4: Vincent Rijmen
 *
 * This code is placed in the public domain.
 */

#include "config_xor.h"

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifdef SH_ENCRYPT

#include "rijndael-api-fst.h"

int makeKey(keyInstance *key, RIJ_BYTE direction, int keyLen, char *keyMaterial) {
  word8 k[MAXKC][4];
  int i;
  char *keyMat;
  
  if (key == NULL) {
    return BAD_KEY_INSTANCE;
  }
  
  if ((direction == DIR_ENCRYPT) || (direction == DIR_DECRYPT)) {
    key->direction = direction;
  } else {
    return BAD_KEY_DIR;
  }
  
  if ((keyLen == 128) || (keyLen == 192) || (keyLen == 256)) { 
    key->keyLen = keyLen;
  } else {
    return BAD_KEY_MAT;
  }
  
  if (keyMaterial != NULL) {
    strncpy(key->keyMaterial, keyMaterial, keyLen/4);
  }
  
  key->ROUNDS = keyLen/32 + 6;
  
  /* initialize key schedule: */
  keyMat = key->keyMaterial;
#ifndef BINARY_KEY_MATERIAL
  for (i = 0; i < key->keyLen/8; i++) {
    int t, j;
    
    t = *keyMat++;
    if ((t >= '0') && (t <= '9')) j = (t - '0') << 4;
    else if ((t >= 'a') && (t <= 'f')) j = (t - 'a' + 10) << 4; 
    else if ((t >= 'A') && (t <= 'F')) j = (t - 'A' + 10) << 4; 
    else return BAD_KEY_MAT;
    
    t = *keyMat++;
    if ((t >= '0') && (t <= '9')) j ^= (t - '0');
    else if ((t >= 'a') && (t <= 'f')) j ^= (t - 'a' + 10); 
    else if ((t >= 'A') && (t <= 'F')) j ^= (t - 'A' + 10); 
    else return BAD_KEY_MAT;
    
    k[i >> 2][i & 3] = (word8)j; 
  }
#else
  for (i = 0; i < key->keyLen/8; i++) {
    k[i >> 2][i & 3] = (word8)keyMat[i]; 
  }
#endif /* ?BINARY_KEY_MATERIAL */
  rijndaelKeySched(k, key->keySched, key->ROUNDS);
  if (direction == DIR_DECRYPT) {
    rijndaelKeyEncToDec(key->keySched, key->ROUNDS);
  }
  
  return TRUE;
}

int cipherInit(cipherInstance *cipher, RIJ_BYTE mode, char *IV) {
  if ((mode == MODE_ECB) || (mode == MODE_CBC) || (mode == MODE_CFB1)) {
    cipher->mode = mode;
  } else {
    return BAD_CIPHER_MODE;
  }
  if (IV != NULL) {
#ifndef BINARY_KEY_MATERIAL
    int i;
    for (i = 0; i < MAX_IV_SIZE; i++) {
      int t, j;
      
      t = IV[2*i];
      if ((t >= '0') && (t <= '9')) j = (t - '0') << 4;
      else if ((t >= 'a') && (t <= 'f')) j = (t - 'a' + 10) << 4; 
      else if ((t >= 'A') && (t <= 'F')) j = (t - 'A' + 10) << 4; 
      else return BAD_CIPHER_INSTANCE;
      
      t = IV[2*i+1];
      if ((t >= '0') && (t <= '9')) j ^= (t - '0');
      else if ((t >= 'a') && (t <= 'f')) j ^= (t - 'a' + 10); 
      else if ((t >= 'A') && (t <= 'F')) j ^= (t - 'A' + 10); 
      else return BAD_CIPHER_INSTANCE;
      
      cipher->IV[i] = (word8)j;
    }
#else
    memcpy(cipher->IV, IV, MAX_IV_SIZE);
#endif /* ?BINARY_KEY_MATERIAL */
  } else {
    memset(cipher->IV, 0, MAX_IV_SIZE);
  }
  return TRUE;
}

int blockEncrypt(cipherInstance *cipher, keyInstance *key,
		 RIJ_BYTE *input, int inputLen, RIJ_BYTE *outBuffer) {
  int i, k, numBlocks;
  union {
    word32 bloc4[4];
    word8  block[16];
  } bb;
  union {
    word32 i4[4];
    word8  iv[4][4];
  } iu;
  
  if (cipher == NULL ||
      key == NULL ||
      key->direction == DIR_DECRYPT) {
    return BAD_CIPHER_STATE;
  }
  if (input == NULL || inputLen <= 0) {
    return 0; /* nothing to do */
  }
  
  numBlocks = inputLen/128;
  
  switch (cipher->mode) {
  case MODE_ECB: 
    for (i = numBlocks; i > 0; i--) {
      rijndaelEncrypt(input, outBuffer, key->keySched, key->ROUNDS);
      input += 16;
      outBuffer += 16;
    }
    break;
    
  case MODE_CBC:
    /* fix the memory alignment for HP-UX 10.20 
     * R. Wichmann  Mon Jun 18 22:36:55 CEST 2001
     */
#if STRICT_ALIGN 
    memcpy(iu.iv, cipher->IV, 16); 
    bb.bloc4[0] = iu.i4[0] ^ ((word32*)input)[0];
    bb.bloc4[1] = iu.i4[1] ^ ((word32*)input)[1];
    bb.bloc4[2] = iu.i4[2] ^ ((word32*)input)[2];
    bb.bloc4[3] = iu.i4[3] ^ ((word32*)input)[3];
#else  /* !STRICT_ALIGN */
    ((word32*)block)[0] = ((word32*)cipher->IV)[0] ^ ((word32*)input)[0];
    ((word32*)block)[1] = ((word32*)cipher->IV)[1] ^ ((word32*)input)[1];
    ((word32*)block)[2] = ((word32*)cipher->IV)[2] ^ ((word32*)input)[2];
    ((word32*)block)[3] = ((word32*)cipher->IV)[3] ^ ((word32*)input)[3];
#endif /* ?STRICT_ALIGN */
    rijndaelEncrypt(bb.block, outBuffer, key->keySched, key->ROUNDS);
    input += 16;
    for (i = numBlocks - 1; i > 0; i--) {
      bb.bloc4[0] = ((word32*)outBuffer)[0] ^ ((word32*)input)[0];
      bb.bloc4[1] = ((word32*)outBuffer)[1] ^ ((word32*)input)[1];
      bb.bloc4[2] = ((word32*)outBuffer)[2] ^ ((word32*)input)[2];
      bb.bloc4[3] = ((word32*)outBuffer)[3] ^ ((word32*)input)[3];
      outBuffer += 16;
      rijndaelEncrypt(bb.block, outBuffer, key->keySched, key->ROUNDS);
      input += 16;
    }
    break;
    
  case MODE_CFB1:
#if STRICT_ALIGN 
    memcpy(iu.iv, cipher->IV, 16); 
#else  /* !STRICT_ALIGN */
    *((word32*)iv[0]) = *((word32*)(cipher->IV   ));
    *((word32*)iv[1]) = *((word32*)(cipher->IV+ 4));
    *((word32*)iv[2]) = *((word32*)(cipher->IV+ 8));
    *((word32*)iv[3]) = *((word32*)(cipher->IV+12));
#endif /* ?STRICT_ALIGN */
    for (i = numBlocks; i > 0; i--) {
      for (k = 0; k < 128; k++) {
	bb.bloc4[0] = iu.i4[0];
	bb.bloc4[1] = iu.i4[1];
	bb.bloc4[2] = iu.i4[2];
	bb.bloc4[3] = iu.i4[3];
	rijndaelEncrypt(bb.block, bb.block, key->keySched, key->ROUNDS);
	outBuffer[k/8] ^= (bb.block[0] & 0x80) >> (k & 7);
	iu.iv[0][0] = (iu.iv[0][0] << 1) | (iu.iv[0][1] >> 7);
	iu.iv[0][1] = (iu.iv[0][1] << 1) | (iu.iv[0][2] >> 7);
	iu.iv[0][2] = (iu.iv[0][2] << 1) | (iu.iv[0][3] >> 7);
	iu.iv[0][3] = (iu.iv[0][3] << 1) | (iu.iv[1][0] >> 7);
	iu.iv[1][0] = (iu.iv[1][0] << 1) | (iu.iv[1][1] >> 7);
	iu.iv[1][1] = (iu.iv[1][1] << 1) | (iu.iv[1][2] >> 7);
	iu.iv[1][2] = (iu.iv[1][2] << 1) | (iu.iv[1][3] >> 7);
	iu.iv[1][3] = (iu.iv[1][3] << 1) | (iu.iv[2][0] >> 7);
	iu.iv[2][0] = (iu.iv[2][0] << 1) | (iu.iv[2][1] >> 7);
	iu.iv[2][1] = (iu.iv[2][1] << 1) | (iu.iv[2][2] >> 7);
	iu.iv[2][2] = (iu.iv[2][2] << 1) | (iu.iv[2][3] >> 7);
	iu.iv[2][3] = (iu.iv[2][3] << 1) | (iu.iv[3][0] >> 7);
	iu.iv[3][0] = (iu.iv[3][0] << 1) | (iu.iv[3][1] >> 7);
	iu.iv[3][1] = (iu.iv[3][1] << 1) | (iu.iv[3][2] >> 7);
	iu.iv[3][2] = (iu.iv[3][2] << 1) | (iu.iv[3][3] >> 7);
	iu.iv[3][3] = (iu.iv[3][3] << 1) | ((outBuffer[k/8] >> (7-(k&7))) & 1);
      }
    }
    break;
    
  default:
    return BAD_CIPHER_STATE;
  }
  
  return 128*numBlocks;
}

int blockDecrypt(cipherInstance *cipher, keyInstance *key,
		 RIJ_BYTE *input, int inputLen, RIJ_BYTE *outBuffer) {
  int i, k, numBlocks;
  union {
    word32 bloc4[4];
    word8  block[16];
  } bb;
  union {
    word32 i4[4];
    word8  iv[4][4];
  } iu;
  
  if (cipher == NULL ||
      key == NULL ||
      ((cipher->mode != MODE_CFB1) && (key->direction == DIR_ENCRYPT))) {
    return BAD_CIPHER_STATE;
  }
  if (input == NULL || inputLen <= 0) {
    return 0; /* nothing to do */
  }
  
  numBlocks = inputLen/128;
  
  switch (cipher->mode) {
  case MODE_ECB: 
    for (i = numBlocks; i > 0; i--) { 
      rijndaelDecrypt(input, outBuffer, key->keySched, key->ROUNDS);
      input += 16;
      outBuffer += 16;
    }
    break;
    
  case MODE_CBC:
#if STRICT_ALIGN 
    memcpy(iu.iv, cipher->IV, 16); 
#else
    *((word32*)iu.i4[0]) = *((word32*)(cipher->IV   ));
    *((word32*)iu.i4[1]) = *((word32*)(cipher->IV+ 4));
    *((word32*)iu.i4[2]) = *((word32*)(cipher->IV+ 8));
    *((word32*)iu.i4[3]) = *((word32*)(cipher->IV+12));
#endif
    for (i = numBlocks; i > 0; i--) {
      rijndaelDecrypt(input, bb.block, key->keySched, key->ROUNDS);
      bb.bloc4[0] ^= iu.i4[0];
      bb.bloc4[1] ^= iu.i4[1];
      bb.bloc4[2] ^= iu.i4[2];
      bb.bloc4[3] ^= iu.i4[3];
#if STRICT_ALIGN
      memcpy(iu.iv, input, 16);
      memcpy(outBuffer, bb.block, 16);
#else
      *((word32*)iv[0]) = ((word32*)input)[0]; ((word32*)outBuffer)[0] = ((word32*)block)[0];
      *((word32*)iv[1]) = ((word32*)input)[1]; ((word32*)outBuffer)[1] = ((word32*)block)[1];
      *((word32*)iv[2]) = ((word32*)input)[2]; ((word32*)outBuffer)[2] = ((word32*)block)[2];
      *((word32*)iv[3]) = ((word32*)input)[3]; ((word32*)outBuffer)[3] = ((word32*)block)[3];
#endif
      input += 16;
      outBuffer += 16;
    }
    break;
    
  case MODE_CFB1:
#if STRICT_ALIGN 
    memcpy(iu.iv, cipher->IV, 16); 
#else
    *((word32*)iv[0]) = *((word32*)(cipher->IV));
    *((word32*)iv[1]) = *((word32*)(cipher->IV+ 4));
    *((word32*)iv[2]) = *((word32*)(cipher->IV+ 8));
    *((word32*)iv[3]) = *((word32*)(cipher->IV+12));
#endif
    for (i = numBlocks; i > 0; i--) {
      for (k = 0; k < 128; k++) {
	bb.bloc4[0] = iu.i4[0];
	bb.bloc4[1] = iu.i4[1];
	bb.bloc4[2] = iu.i4[2];
	bb.bloc4[3] = iu.i4[3];
	rijndaelEncrypt(bb.block, bb.block, key->keySched, key->ROUNDS);
	iu.iv[0][0] = (iu.iv[0][0] << 1) | (iu.iv[0][1] >> 7);
	iu.iv[0][1] = (iu.iv[0][1] << 1) | (iu.iv[0][2] >> 7);
	iu.iv[0][2] = (iu.iv[0][2] << 1) | (iu.iv[0][3] >> 7);
	iu.iv[0][3] = (iu.iv[0][3] << 1) | (iu.iv[1][0] >> 7);
	iu.iv[1][0] = (iu.iv[1][0] << 1) | (iu.iv[1][1] >> 7);
	iu.iv[1][1] = (iu.iv[1][1] << 1) | (iu.iv[1][2] >> 7);
	iu.iv[1][2] = (iu.iv[1][2] << 1) | (iu.iv[1][3] >> 7);
	iu.iv[1][3] = (iu.iv[1][3] << 1) | (iu.iv[2][0] >> 7);
	iu.iv[2][0] = (iu.iv[2][0] << 1) | (iu.iv[2][1] >> 7);
	iu.iv[2][1] = (iu.iv[2][1] << 1) | (iu.iv[2][2] >> 7);
	iu.iv[2][2] = (iu.iv[2][2] << 1) | (iu.iv[2][3] >> 7);
	iu.iv[2][3] = (iu.iv[2][3] << 1) | (iu.iv[3][0] >> 7);
	iu.iv[3][0] = (iu.iv[3][0] << 1) | (iu.iv[3][1] >> 7);
	iu.iv[3][1] = (iu.iv[3][1] << 1) | (iu.iv[3][2] >> 7);
	iu.iv[3][2] = (iu.iv[3][2] << 1) | (iu.iv[3][3] >> 7);
	iu.iv[3][3] = (iu.iv[3][3] << 1) | ((input[k/8] >> (7-(k&7))) & 1);
	outBuffer[k/8] ^= (bb.block[0] & 0x80) >> (k & 7);
      }
    }
    break;
    
  default:
    return BAD_CIPHER_STATE;
  }
  
  return 128*numBlocks;
}
#ifdef INTERMEDIATE_VALUE_KAT
/**
 *	cipherUpdateRounds:
 *
 *	Encrypts/Decrypts exactly one full block a specified number of rounds.
 *	Only used in the Intermediate Value Known Answer Test.	
 *
 *	Returns:
 *		TRUE - on success
 *		BAD_CIPHER_STATE - cipher in bad state (e.g., not initialized)
 */
int cipherUpdateRounds(cipherInstance *cipher, keyInstance *key,
		RIJ_BYTE *input, int inputLen, RIJ_BYTE *outBuffer, int rounds) {
	int j;
	word8 block[4][4];

	if (cipher == NULL || key == NULL) {
		return BAD_CIPHER_STATE;
	}

	for (j = 3; j >= 0; j--) {
		/* parse input stream into rectangular array */
  		*((word32*)block[j]) = *((word32*)(input+4*j));
	}

	switch (key->direction) {
	case DIR_ENCRYPT:
		rijndaelEncryptRound(block, key->keySched, key->ROUNDS, rounds);
		break;
		
	case DIR_DECRYPT:
		rijndaelDecryptRound(block, key->keySched, key->ROUNDS, rounds);
		break;
		
	default:
		return BAD_KEY_DIR;
	} 

	for (j = 3; j >= 0; j--) {
		/* parse rectangular array into output ciphertext bytes */
		*((word32*)(outBuffer+4*j)) = *((word32*)block[j]);
	}
	
	return TRUE;
}
#endif /* INTERMEDIATE_VALUE_KAT */
#endif
