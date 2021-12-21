/* Fhsha256.h -- FHSHA-256
2021-10-28*/

#ifndef FHSHA256_H
#define FHSHA256_H

#include <stdlib.h>
#include <stdint.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

class FHSHA256{

  public:

    std::vector<LweSample*> state;
    std::vector<LweSample*> Wt_Encrypted;
    std::vector<LweSample*>  lastRoundState;
    TFheGateBootstrappingCloudKeySet* bk;
    int group;

    FHSHA256(TFheGateBootstrappingCloudKeySet* public_key);
    void FHsha256_H0_init();
    void FHsha256_Kt_Encrypted(LweSample*& Kt, int t);
    void FHsha256_Ch(LweSample*& ch, std::vector<LweSample*> tempState);
    void FHsha256_Ma(LweSample*& Ma, std::vector<LweSample*> tempState);
    void FHsha256_sigma0(LweSample*& sigma0, std::vector<LweSample*> tempState);
    void FHsha256_sigma1(LweSample*& sigma1, std::vector<LweSample*> tempState);
    void FHsha256_transform(int r, int groupIndex);
    void FHsha256_transformFinal(uint32_t *finalState, uint32_t *finalRoundState, uint32_t *finalWt, int round);

    void FHsha256_updateFor64(size_t elementSize, int round);
  
  private:
    void FHsha256_readCipher(int groupIndex, int elementIndex);
    void rotateRightBitwiseShift(LweSample* output, const LweSample* input, const long shamt);
    void rightBitwiseShift(LweSample* output, const LweSample* input, const long shamt);
    void elementAdd(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits);
    uint32_t rotr(uint32_t x, uint32_t n);
    uint32_t choose(uint32_t e, uint32_t f, uint32_t g);
    uint32_t majority(uint32_t a, uint32_t b, uint32_t c);
};

#endif
