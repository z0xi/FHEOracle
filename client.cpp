#include <iostream>
#include <string.h>
#include "holder.h"
#include <helib/helib.h>

int main (void) {

  HOLDER holder;
  holder.keygen();
  uint8_t buf[56] = {0x1,0x2,0x3,0x4,0x5,0x6, 0x7,0x8, 
    0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8, 
    0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8};
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8};

  std::ifstream con,pkfile;                              
  con.open("context");
  helib::Context context =  helib::Context::readFrom(con);
  con.close();
  pkfile.open("pk");
  helib::PubKey public_key = helib::PubKey::readFrom(pkfile,context);
  pkfile.close();
  helib::Ctxt scratch(public_key);

  long elementSize;
  uint8_t *mes = holder.messagePad(elementSize, sizeof(buf), buf);
  std::vector<std::vector<helib::Ctxt>> encrypted_M(elementSize / 16 * 64, std::vector<helib::Ctxt>(32, scratch));;
  for( int i = 0; i < elementSize / 16; i++){
    uint32_t *wtMessage = new uint32_t[4*64];
    holder.wtExpand(wtMessage, mes + i * 64);
    holder.bgvEncryptElementWise(encrypted_M, public_key, wtMessage, i);
    delete wtMessage;
  }
  std::cout << "Encrypted finished" << std::endl;
}
 
