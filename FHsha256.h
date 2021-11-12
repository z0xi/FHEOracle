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
    // std::vector<std::vector<helib::Ctxt> > Kt_Encrypted;
    std::vector<std::vector<helib::Ctxt> > Wt_Encrypted;
    const helib::PubKey& public_key;
    int group;
    // helib::EncryptedArray ea;

    FHSHA256(const helib::PubKey& newPubKey);
    void FHsha256_H0_init();
    void FHsha256_update(std::vector<std::vector<helib::Ctxt> >  data, size_t elementSize, int round);

    void FHsha256_Wt_init(std::vector<std::vector<helib::Ctxt> > data);
    void FHsha256_Wt_create(int t);
    void FHsha256_Kt_Encrypted(std::vector<helib::Ctxt>& Kt, int t);
    void FHsha256_Ch(std::vector<helib::Ctxt>& ch);
    void FHsha256_Ma(std::vector<helib::Ctxt>& Ma);
    void FHsha256_sigma0(std::vector<helib::Ctxt>& sigma0);
    void FHsha256_sigma1(std::vector<helib::Ctxt>& sigma1);
    void FHsha256_transform(int r, int groupIndex);
    // void FHsha256_final(FHsha256_t *p, unsigned char *digest);
  
};

#endif
