/* hold.h
2021-12-20*/

#ifndef HOLDER_H
#define HOLDER_H

#include <stdlib.h>
#include <stdint.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

class HOLDER{

  public:
    HOLDER();
    void keygen();
    uint8_t* messagePad(long& elementSize, uint32_t m_blocklen, uint8_t *input);
    void bgvEncryptElementWise( TFheGateBootstrappingSecretKeySet* key, const TFheGateBootstrappingParameterSet* params, uint32_t *message, long elementIndex);
    void wtExpand(uint32_t *output , uint8_t *input);
};

#endif
