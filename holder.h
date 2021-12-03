/* hold.h
2021-12-01*/

#ifndef HOLDER_H
#define HOLDER_H

#include <stdlib.h>
#include <stdint.h>
#include <helib/helib.h>

class HOLDER{

  public:
    HOLDER();
    void keygen();
    uint8_t* messagePad(long& elementSize, uint32_t m_blocklen, uint8_t *input);
    void bgvEncryptBitWise(std::vector<helib::Ctxt>& encrypted_M, const helib::PubKey& public_key, uint8_t *buf, long bitSize);
    void bgvEncryptElementWise(std::vector<std::vector<helib::Ctxt>>& encrypted_M, const helib::PubKey& public_key, uint32_t *message, long elementIndex);
    void wtExpand(uint32_t *output , uint8_t *input);
};

#endif
