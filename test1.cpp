#include <iostream>
#include <assert.h>
#include <string.h>
#include "FHsha256.h"
#include "SHA256.h"
#include "holder.h"
#include <helib/helib.h>
#include <helib/binaryArith.h>
#include <helib/intraSlot.h>

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
  // int sendMessageSize = 16 * 3;

  // std::ofstream ciphertext;
  // std::ofstream ciphertext1;
  // ciphertext.open("ciphertext.json");
  // ciphertext1.open("ciphertext1.json");
  // encrypted[0][0].writeToJSON(ciphertext);
  // encrypted[0][2].writeToJSON(ciphertext1);
  // ciphertext.close();
  // ciphertext1.close();

  int round = 63;
  std::vector<std::vector<helib::Ctxt>> padMessage;
  FHSHA256 hash(public_key);
  hash.FHsha256_H0_init();
  // hash.FHsha256_Wt_init(encrypted);
  // hash.FHsha256_Wt_create(16);
  // hash.FHsha256_Wt_create(17);
  // hash.FHsha256_Kt_Encrypted(0);
  // std::vector<helib::Ctxt> ch;
  // std::vector<helib::Ctxt> ma;
  // std::vector<helib::Ctxt> sigma0;
  // std::vector<helib::Ctxt> sigma1;
  // hash.FHsha256_Ch(ch);
  // hash.FHsha256_Ma(ma);
  // hash.FHsha256_sigma0(sigma0);
  // hash.FHsha256_sigma1(sigma1);
  // hash.FHsha256_transform(0);
  hash.FHsha256_updateFor64(encrypted_M, elementSize / 16 * 64, round);

  // uint32_t roundState[8];
  // uint32_t lastState[8];
  uint32_t finalState[8];
  std::ifstream skfile;
  skfile.open("sk");
  const helib::EncryptedArray& ea = context.getEA();

  helib::SecKey secret_key = helib::SecKey::readFrom(skfile,context);
  skfile.close();
  std::cout << "Compute message hash using FHSHA256" << std::endl;
  // std::cout << "Final group "<< round << " state A-H decrypt:";
  // for(int i = 0;i < 8; i++){
  //   std::vector<long> decrypted_result;
  //   helib::CtPtrs_vectorCt result_wrapper(hash.state[i]);
  //   helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  //   memcpy(&roundState[i], &decrypted_result[0], 32);
  //   std::cout << std::hex<< decrypted_result[0] << std::endl;
  // }
  std::cout << "Final group  state A-H decrypt:";
  for(int i = 0;i < 8; i++){
    std::vector<long> decrypted_result;
    helib::CtPtrs_vectorCt result_wrapper(hash.state[i]);
    helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
    memcpy(&finalState[i], &decrypted_result[0], 32);
    std::cout << std::hex<< decrypted_result[0];
  }
  std::cout << std::endl;
  // uint8_t * hhh = new uint8_t[32];
  // hash.FHsha256_digest(hhh, finalState);
  // std::cout << "Compute message hash using FHSHA256" << std::endl;
	// std::cout << "hash:" << hash.toString(hhh) << std::endl;

  // std::cout << "Final group hash state decrypt:" << std::endl;
  // for(int i = 0;i < 8; i++){
  //   std::vector<long> decrypted_result;
  //   helib::CtPtrs_vectorCt result_wrapper(hash.state[i]);
  //   helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  //   memcpy(&lastState[i], &decrypted_result[0], 32);
  //   std::cout << std::hex<< decrypted_result[0] << std::endl;
  // }
  // std::cout << "Compute the rest of transform:" << std::endl;
  // hash.FHsha256_updateFinal(finalState, roundState, 63 - round);


  std::cout << std::endl;
  // char messageCheck[128];
  // memcpy(messageCheck, buf,64);
  std::cout << "Compute message hash using SHA256" << std::endl;
  
  SHA256 sha;
  sha.update(reinterpret_cast<char*>(buf));
  uint8_t * digest = sha.digest();

  std::cout << "hash:"<<SHA256::toString(digest) << std::endl;

}
 
