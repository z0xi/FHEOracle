/* Crypto/Sha256.c -- SHA-256 Hash
2021-10-28*/

#include <iostream>
#include "FHsha256.h"
#include "string.h"
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <thread>
#include <ctime>


uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
uint32_t H0[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};


FHSHA256::FHSHA256(TFheGateBootstrappingCloudKeySet* newPubKey) : bk(newPubKey){
  }


void 
FHSHA256::rotateRightBitwiseShift(LweSample* output, const LweSample* input, const long shamt)
{
  for (long i = 0; i < 32 - shamt; ++i)
    bootsCOPY(&output[i], &input[i + shamt], bk);
  for (long i = 32 - shamt, j = 0; i < 32; ++i, ++j)
    bootsCOPY(&output[i], &input[j], bk);
}

void 
FHSHA256::rightBitwiseShift(LweSample* output, const LweSample* input, const long shamt)
{
  for (long i = 0; i < 32 - shamt; ++i)
    bootsCOPY(&output[i], &input[i + shamt], bk);
  for (long i = 32 - shamt, j = 0; i < 32; ++i, ++j)
    bootsCONSTANT(&output[i], 0, bk);
}

void
FHSHA256::FHsha256_H0_init()
{
  //H0 init
  const TFheGateBootstrappingParameterSet* params = bk->params;
  for(int i = 0; i<8; i++){
    LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(32, params);
    for (int j=0; j<32; j++) {
      bootsCONSTANT(&ciphertext[j], (H0[i]>>j)&1, bk);
    }
    state.push_back(ciphertext);
  }
  std::cout<<"H0"<<" init"<<" finished\n";
}


void 
FHSHA256::FHsha256_Kt_Encrypted(LweSample*& Kt_Encrypted ,int t){
  for (int j=0; j<32; j++) {
      bootsCONSTANT(&Kt_Encrypted[j], (K[t]>>j)&1, bk);
  }
  std::cout<<"K"<<t<<" encrypted"<<" finished\n";
}

void
FHSHA256::FHsha256_Ch(LweSample*& ch, std::vector<LweSample*> tempState){
  const TFheGateBootstrappingParameterSet* params = bk->params;
  LweSample* temp1 = new_gate_bootstrapping_ciphertext_array(32, params);
  LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(32, params);
  LweSample* temp3 = new_gate_bootstrapping_ciphertext_array(32, params);
  for(int i = 0;i < 32; i++){
    bootsAND(&temp1[i], &tempState[4][i], &tempState[5][i], bk);
  }
  for(int i = 0;i < 32; i++){
    bootsNOT(&temp2[i], &tempState[4][i], bk);
  }
  for(int i = 0;i < 32; i++){
    bootsAND(&temp3[i], &temp2[i], &tempState[6][i], bk);
  }
  for(int i = 0;i < 32; i++){
    bootsXOR(&ch[i], &temp3[i], &temp1[i], bk);
  }
};

void 
FHSHA256::FHsha256_Ma(LweSample*& Ma, std::vector<LweSample*> tempState){

  const TFheGateBootstrappingParameterSet* params = bk->params;
  LweSample* temp1 = new_gate_bootstrapping_ciphertext_array(32, params);
  LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(32, params);
  LweSample* temp3 = new_gate_bootstrapping_ciphertext_array(32, params);
  for(int i = 0;i < 32; i++){
    bootsAND(&temp1[i], &tempState[0][i], &tempState[1][i], bk);
  }
  for(int i = 0;i < 32; i++){
    bootsAND(&temp2[i], &tempState[0][i], &tempState[2][i], bk);
  }
  for(int i = 0;i < 32; i++){
    bootsXOR(&temp3[i], &temp1[i], &temp2[i], bk);
  }
  for(int i = 0;i < 32; i++){
    bootsAND(&temp1[i], &tempState[1][i], &tempState[2][i], bk);
  }
  for(int i = 0;i < 32; i++){
    bootsXOR(&Ma[i], &temp3[i], &temp1[i], bk);
  }
};

void 
FHSHA256::FHsha256_sigma0(LweSample*& sigma0, std::vector<LweSample*> tempState){
  const TFheGateBootstrappingParameterSet* params = bk->params;
  LweSample* temp1 = new_gate_bootstrapping_ciphertext_array(32, params);
  LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(32, params);
  LweSample* temp3 = new_gate_bootstrapping_ciphertext_array(32, params);
  rotateRightBitwiseShift(temp1, tempState[0], 2);
  rotateRightBitwiseShift(temp2, tempState[0], 13);
  for(int i = 0;i < 32; i++){
    bootsXOR(&temp3[i], &temp1[i], &temp2[i], bk);
  }
  rotateRightBitwiseShift(temp1, tempState[0], 22);
  for(int i = 0;i < 32; i++){
    bootsXOR(&sigma0[i], &temp3[i], &temp1[i], bk);
  }
};

void 
FHSHA256::FHsha256_sigma1(LweSample*& sigma1, std::vector<LweSample*> tempState){
  const TFheGateBootstrappingParameterSet* params = bk->params;
  LweSample* temp1 = new_gate_bootstrapping_ciphertext_array(32, params);
  LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(32, params);
  LweSample* temp3 = new_gate_bootstrapping_ciphertext_array(32, params);

  rotateRightBitwiseShift(temp1, tempState[4], 6);
  rotateRightBitwiseShift(temp2, tempState[4], 11);
  for(int i = 0;i < 32; i++){
    bootsXOR(&temp3[i], &temp1[i], &temp2[i], bk);
  }
  rotateRightBitwiseShift(temp2, tempState[4], 25);
  for(int i = 0;i < 32; i++){
    bootsXOR(&sigma1[i], &temp3[i], &temp2[i], bk);
  }
};

void 
FHSHA256::elementAdd(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits) {
  LweSample* tmps = new_gate_bootstrapping_ciphertext_array(4, bk->params);

  //initialize the carry to 0
  bootsCONSTANT(&tmps[0], 0, bk);
  bootsCONSTANT(&tmps[1], 0, bk);
  bootsCONSTANT(&tmps[2], 0, bk);
  bootsCONSTANT(&tmps[3], 0, bk);
  //run the elementary comparator gate n times
  for (int i=0; i<nb_bits; i++) {
      bootsXOR(&tmps[1], &a[i], &b[i], bk);
      bootsAND(&tmps[2], &a[i], &b[i], bk);
      bootsXOR(&result[i], &tmps[1], &tmps[0], bk);
      bootsAND(&tmps[3], &tmps[0], &tmps[1], bk);
      bootsOR(&tmps[0], &tmps[2], &tmps[3], bk);
  }
  delete_gate_bootstrapping_ciphertext_array(4, tmps);
}

void 
FHSHA256::FHsha256_transform(int round, int groupIndex){
  FILE* secret_key = fopen("secret.key","rb");
  TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
  fclose(secret_key);
  const TFheGateBootstrappingParameterSet* params = bk->params;
  std::vector<LweSample*>  tempState;
  for(int i = 0;i < 8; i++){
    LweSample* tmp = new_gate_bootstrapping_ciphertext_array(32, params);
    for(int j = 0; j<32; j++)
      bootsCOPY(&tmp[j], &state[i][j], bk);
    tempState.push_back(tmp);
  }
  int roundNum = 63;
  if(groupIndex == group)
    roundNum = round;
  for( int r = 0; r <= roundNum; r++){
    LweSample* Kt = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ch = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* ma = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* sigma0 = new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* sigma1 = new_gate_bootstrapping_ciphertext_array(32, params);
  
    FHsha256_Kt_Encrypted(Kt ,r);
    FHsha256_Ch(ch, tempState);
    FHsha256_Ma(ma, tempState);
    FHsha256_sigma0(sigma0, tempState);
    FHsha256_sigma1(sigma1, tempState);
    int32_t int_answer = 0;
  
    std::cout<<"ch ma sigma1 sigma0"<<" generated\n";
    LweSample* temp1= new_gate_bootstrapping_ciphertext_array(32, params);
    LweSample* temp2= new_gate_bootstrapping_ciphertext_array(32, params);
    elementAdd(temp1, ch, tempState[7], 32);
    elementAdd(temp2, temp1, Wt_Encrypted[r], 32);
    elementAdd(temp1, temp2, Kt, 32);
    elementAdd(temp2, temp1, sigma1, 32);

    for(int i =0; i <32;i++){
      bootsCOPY(&tempState[7][i], &tempState[6][i], bk);
      bootsCOPY(&tempState[6][i], &tempState[5][i], bk);
      bootsCOPY(&tempState[5][i], &tempState[4][i], bk);
    }

    elementAdd(tempState[4], tempState[3], temp2, 32);
    elementAdd(temp1, temp2, ma, 32);

    for(int i =0; i <32;i++){
      bootsCOPY(&tempState[3][i], &tempState[2][i], bk);
      bootsCOPY(&tempState[2][i], &tempState[1][i], bk);
      bootsCOPY(&tempState[1][i], &tempState[0][i], bk);
    }

    elementAdd(tempState[0], temp1, sigma0, 32);

    for (int i=0; i<32; i++) {
        int ai = bootsSymDecrypt(&tempState[0][i], key);
        int_answer |= (ai<<i);
    }
    std::cout << "A = "<<std::hex << int_answer << std::endl;
    std::cout<<"Round "<< r <<" A-H generated\n";
  }
  if(roundNum == 63 && groupIndex != group){
    std::vector<LweSample*>  tempState_1;
    for(int i = 0;i < 8; i++){
      LweSample* tmp = new_gate_bootstrapping_ciphertext_array(32, params);
      for(int j = 0; j<32; j++)
        bootsCOPY(&tmp[j], &state[i][j], bk);
      tempState_1.push_back(tmp);
    }
    elementAdd(state[0], tempState[0], tempState_1[0], 32);
    elementAdd(state[1], tempState[1], tempState_1[1], 32);
    elementAdd(state[2], tempState[2], tempState_1[2], 32);
    elementAdd(state[3], tempState[3], tempState_1[3], 32);
    elementAdd(state[4], tempState[4], tempState_1[4], 32);
    elementAdd(state[5], tempState[5], tempState_1[5], 32);
    elementAdd(state[6], tempState[6], tempState_1[6], 32);
    elementAdd(state[7], tempState[7], tempState_1[7], 32);
    std::cout<<"Group "<< groupIndex << " hash generated\n";
  }
  if( groupIndex == group ){
    for( int i = 0; i < 8; i++)
      lastRoundState.push_back(tempState[i]);
  }
};

void
FHSHA256::FHsha256_readCipher(int groupIndex, int elementIndex){

  const TFheGateBootstrappingParameterSet* params = bk->params;
  char tmp[20];
  LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(32, params);
  std::sprintf(tmp,"./EM/C_%d_%d",groupIndex ,elementIndex);
  FILE* cloud_data = fopen(tmp,"rb");
  for(int i = 0;i < 32;i++){
    import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext[i], params);
  }
  fclose(cloud_data);
  Wt_Encrypted.push_back(ciphertext);
};

void
FHSHA256::FHsha256_updateFor64(size_t elementSize, int round){
  int elementIndex = 0;
  group = elementSize / 64;
  int groupIndex = 1;
  // P.S. 1 elementSize = 32bits
  while (elementSize > 0)
  {
    FHSHA256::FHsha256_readCipher(groupIndex - 1, elementIndex);
    elementIndex++;
    elementSize--;
    if (elementIndex == 64)
    {
      elementIndex = 0;
      FHsha256_transform(round, groupIndex);
      if(groupIndex != group)
        Wt_Encrypted.clear();
      groupIndex++;
    }
  }
};


uint32_t FHSHA256::rotr(uint32_t x, uint32_t n) {
	return (x >> n) | (x << (32 - n));
}

uint32_t FHSHA256::choose(uint32_t e, uint32_t f, uint32_t g) {
	return (e & f) ^ (~e & g);
}

uint32_t FHSHA256::majority(uint32_t a, uint32_t b, uint32_t c) {
	return (a & (b | c)) | (b & c);
}

void FHSHA256::FHsha256_transformFinal(uint32_t *finalState, uint32_t *finalRoundState, uint32_t *finalWt, int round) {
	uint32_t maj, xorA, ch, xorE, sum, newA, newE;

	for (uint8_t i = round + 1; i < 64; i++) {
		maj   = FHSHA256::majority(finalRoundState[0], finalRoundState[1], finalRoundState[2]);
		xorA  = FHSHA256::rotr(finalRoundState[0], 2) ^ FHSHA256::rotr(finalRoundState[0], 13) ^ FHSHA256::rotr(finalRoundState[0], 22);

		ch = FHSHA256::choose(finalRoundState[4], finalRoundState[5], finalRoundState[6]);

		xorE  = FHSHA256::rotr(finalRoundState[4], 6) ^ FHSHA256::rotr(finalRoundState[4], 11) ^ FHSHA256::rotr(finalRoundState[4], 25);

		sum  = finalWt[i - round - 1] + K[i] + finalRoundState[7] + ch + xorE;
		newA = xorA + maj + sum;
		newE = finalRoundState[3] + sum;

		finalRoundState[7] = finalRoundState[6];
		finalRoundState[6] = finalRoundState[5];
		finalRoundState[5] = finalRoundState[4];
		finalRoundState[4] = newE;
		finalRoundState[3] = finalRoundState[2];
		finalRoundState[2] = finalRoundState[1];
		finalRoundState[1] = finalRoundState[0];
		finalRoundState[0] = newA;
	}

	for(uint8_t i = 0 ; i < 8 ; i++) {
		finalState[i] += finalRoundState[i];
	}
}