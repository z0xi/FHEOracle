/* Fhsha256.h -- FHSHA-256
2021-10-28*/

#ifndef FHSHA256_H
#define FHSHA256_H

#include <stdlib.h>
#include <stdint.h>
#include <helib/helib.h>

class FHSHA256{

  public:

    std::vector<std::vector<helib::Ctxt> > state;
    std::vector<std::vector<helib::Ctxt> > buffer;
    std::vector<std::vector<helib::Ctxt> > Wt_Encrypted;
    std::vector<std::vector<helib::Ctxt> > lastRoundState;
    const helib::PubKey& public_key;
    int group;

    FHSHA256(const helib::PubKey& newPubKey);
    void FHsha256_pad(std::vector<std::vector<helib::Ctxt> >&  output, std::vector<helib::Ctxt>  input, int elementSize);
    void FHsha256_H0_init();
    void FHsha256_update(std::vector<std::vector<helib::Ctxt> >  data, size_t elementSize, int round);
    void FHsha256_Wt_init(std::vector<std::vector<helib::Ctxt> > data);
    void FHsha256_Wt_create(int t);
    void FHsha256_Kt_Encrypted(std::vector<helib::Ctxt>& Kt, int t);
    void FHsha256_Ch(std::vector<helib::Ctxt>& ch, std::vector<std::vector<helib::Ctxt> > tempState);
    void FHsha256_Ma(std::vector<helib::Ctxt>& Ma, std::vector<std::vector<helib::Ctxt> > tempState);
    void FHsha256_sigma0(std::vector<helib::Ctxt>& sigma0, std::vector<std::vector<helib::Ctxt> > tempState);
    void FHsha256_sigma1(std::vector<helib::Ctxt>& sigma1, std::vector<std::vector<helib::Ctxt> > tempState);
    void FHsha256_transform(int r, int groupIndex);
    void FHsha256_transformFinal(uint32_t *finalState, uint32_t *finalRoundState, uint32_t *finalWt, int round);
    

    void FHsha256_updateFor64(size_t elementSize, int round);
    void FHsha256_Wt_initFor64(std::vector<std::vector<helib::Ctxt> > data);
    void FHsha256_transformNoWtCreated(int r, int groupIndex);
  
  private:
    void FHsha256_readCipher(int groupIndex, int elementIndex);
    uint32_t rotr(uint32_t x, uint32_t n);
    uint32_t choose(uint32_t e, uint32_t f, uint32_t g);
    uint32_t majority(uint32_t a, uint32_t b, uint32_t c);
};

#endif
