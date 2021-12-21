#include <iostream>
#include <string.h>
#include "FHsha256.h"
#include "SHA256.h"
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

int main (void) {
  FILE* secret_key = fopen("secret.key","rb");
  TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
  fclose(secret_key);
  //reads the cloud key from file
  FILE* cloud_key = fopen("cloud.key","rb");
  TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
  fclose(cloud_key);

  //if necessary, the params are inside the key
  const TFheGateBootstrappingParameterSet* params = bk->params;

  int round = 16;
  int elementSize = 64 * 2;
  // std::vector<std::vector<LweSample*>> padMessage;
  FHSHA256 hash(bk);
  hash.FHsha256_H0_init();
  hash.FHsha256_updateFor64(elementSize, round);

  uint32_t finalRoundState[8];
  uint32_t lastState[8];
  uint32_t *finalWt = new uint32_t[4*(63 - round)];


  std::cout << "*****Compute message hash using FHSHA256*****" << std::endl;
  std::cout << "Final group "<< round << " round A-H decrypt:" << std::endl;
  for(int i = 0;i < 8; i++){
    uint32_t int_answer = 0;
    for (int j=0; j<32; j++) {
        int ai = bootsSymDecrypt(&hash.lastRoundState[i][j], key);
        int_answer |= (ai<<j);
    }
    memcpy(&finalRoundState[i], &int_answer, 4);
    std::cout << std::hex << int_answer;
  }

  std::cout << std::endl;
  std::cout << "N - 1 group state A-H decrypt:" << std::endl;
  for(int i = 0;i < 8; i++){
    uint32_t int_answer = 0;
    for (int j=0; j<32; j++) {
        int ai = bootsSymDecrypt(&hash.state[i][j], key);
        int_answer |= (ai<<j);
    }
    memcpy(&lastState[i], &int_answer, 4);
    std::cout << std::hex << int_answer;
  }
  
  std::cout << std::endl;
  std::cout << "last Wt decrypt:" << std::endl;
  for(int i = round + 1, k = 0;i < 64; i++, k++){
    uint32_t int_answer = 0;
    for (int j=0; j<32; j++) {
        int ai = bootsSymDecrypt(&hash.Wt_Encrypted[i][j], key);
        int_answer |= (ai<<j);
    }
    memcpy(&finalWt[k], &int_answer, 4);
    std::cout << std::hex << int_answer;
  }
  std::cout << std::endl;
  std::cout << "Compute the rest of transform" << std::endl;
  hash.FHsha256_transformFinal(lastState, finalRoundState, finalWt, round);
  std::cout << "hash:";
  for(int i = 0; i< 8; i++){
	  std::cout << lastState[i];
  }
  std::cout << std::endl;
}
 
