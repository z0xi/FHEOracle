#include <iostream>
#include <assert.h>
#include <string.h>
#include "FHsha256.h"
#include "SHA256.h"

#include <helib/helib.h>
#include <helib/binaryArith.h>
#include <helib/intraSlot.h>

void keygen(){
 // Plaintext prime modulus.
  // long p = 2;
  // // Cyclotomic polynomial - defines phi(m).
  // long m = 4095;
  // // Hensel lifting (default = 1).
  // long r = 1;
  // // Number of bits of the modulus chain.
  // long bits = 600;
  // // Number of columns of Key-Switching matrix (typically 2 or 3).
  // long c = 2;
  // // Factorisation of m required for bootstrapping.
  // std::vector<long> mvec = {7, 5, 9, 13};
  // // Generating set of Zm* group.
  // std::vector<long> gens = {2341, 3277, 911};
  // // Orders of the previous generators.
  // std::vector<long> ords = {6, 4, 6};
 long p = 2;

 long m = 1705;

 long r = 1;
 long bits = 600;
 long c = 2;
 std::vector<long> mvec = {11, 155};
 std::vector<long> gens = { 156,  936};
 std::vector<long> ords = {10,  6};
  std::cout << "Initialising context object..." << std::endl;
  // Initialize the context.
  
  // This object will hold information about the algebra created from the
  // previously set parameters.
  helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .gens(gens)
                               .ords(ords)
                               .bits(bits)
                               .c(c)
                               .bootstrappable(true)
                               .mvec(mvec)
                               .build();
                               
  context.printout();
  std::cout << std::endl;
  // Print the security level.
  std::cout << "Security: " << context.securityLevel() << std::endl;
  std::cout << "Creating secret key..." << std::endl;
  // Create a secret key associated with the context.
  helib::SecKey secret_key(context);
  // Generate the secret key.
  secret_key.GenSecKey();
  addSome1DMatrices(secret_key);
  addFrbMatrices(secret_key);
  // Generate bootstrapping data.
  secret_key.genRecryptData();
  // helib::addFrbMatrices(secret_key);
  // helib::addSome1DMatrices(secret_key);
  // Public key management.
  // Set the secret key (upcast: SecKey is a subclass of PubKey).
   helib::PubKey& public_key = secret_key;

  // 以写模式打开文件
  std::ofstream con;
  con.open("context");
  context.writeTo(con);
  con.close();

  // 以写模式打开文件
  std::ofstream skfile;
  skfile.open("sk");
  secret_key.writeTo(skfile);
  skfile.close();

    // 以写模式打开文件
  std::ofstream pkfile;
  pkfile.open("pk");
  public_key.writeTo(pkfile);
  pkfile.close();

}

int main (void) {

  keygen();
 
  std::ifstream con,pkfile;                              
  con.open("context");

  helib::Context context =  helib::Context::readFrom(con);
  con.close();
  pkfile.open("pk");
  helib::PubKey public_key = helib::PubKey::readFrom(pkfile,context);
  pkfile.close();
  // Get the EncryptedArray of the context.

  const helib::EncryptedArray& ea = context.getEA();

  // // Build the unpack slot encoding.
  std::vector<helib::zzX> unpackSlotEncoding;
  buildUnpackSlotEncoding(unpackSlotEncoding, ea);
  // // Get the number of slot (phi(m)).
  long nslots = ea.size();
  std::cout << "Number of slots: " << nslots << std::endl;
  
  uint8_t buf[54] = {0x1,0x2,0x3,0x4,0x5,0x6, 0x7,0x8, 
    0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8, 
    0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    0x1,0x2,0x3,0x4,0x5,0x6};
  long bitSize = strlen(reinterpret_cast<const char *>(buf)) * 8;
  // uint8_t buf_1[64] = {0x2,0x2,0x3,0x3,0x4,0x4, 0x5,0x5, 
  //   0x2,0x2,0x3,0x3,0x4,0x4, 0x5,0x5,
  //   0x2,0x2,0x3,0x3,0x4,0x4, 0x5,0x5,
  //   0x2,0x2,0x3,0x3,0x4,0x4, 0x5,0x5,
  //   0x2,0x2,0x3,0x3,0x4,0x4, 0x5,0x5,
  //   0x2,0x2,0x3,0x3,0x4,0x4, 0x5,0x5,
  //   0x2,0x2,0x3,0x3,0x4,0x4, 0x5,0x5,
  //   0x2,0x2,0x3,0x3,0x4,0x4, 0x5,0x5,};
  // uint32_t message_1[16];
  // for(int i = 0; i < 16; i++){
  //   memcpy(&message_1[i],&buf_1[ i*4 ],4);
  // }

  // uint8_t buf_pad[64] = {0x80,0x0,0x0,0x0,0x0,0x0, 0x0,0x0, 
  //   0x0,0x0,0x0,0x0,0x0,0x0, 0x0,0x0,
  //   0x0,0x0,0x0,0x0,0x0,0x0, 0x0,0x0,
  //   0x0,0x0,0x0,0x0,0x0,0x0, 0x0,0x0,
  //   0x0,0x0,0x0,0x0,0x0,0x0, 0x0,0x0,
  //   0x0,0x0,0x0,0x0,0x0,0x0, 0x0,0x0,
  //   0x0,0x0,0x0,0x0,0x0,0x0, 0x0,0x0,
  //   0x0,0x0,0x0,0x0,0x0,0x0, 0x4,0x00};
  // uint32_t message_pad[16];
  // for(int i = 0; i < 16; i++){
  //   memcpy(&message_pad[i],&buf_pad[ i*4 ],4);
  // }
  // Use a scratch ciphertext to populate vectors.
  // 16 vector and content is scratch
  helib::Ctxt scratch(public_key);

  std::vector<helib::Ctxt> encrypted_M(bitSize, scratch);
  // Encrypt the data in binary representation.
  for (long i = 0; i < bitSize/8 ; ++i) {
    for( int j = 0; j < 8 ;j++){
      std::vector<long> m_vec(ea.size());
      // Extract the i'th bit of a,b,c.
      for (auto& slot : m_vec)
        slot = ( buf[i] >> j) & 1;
      ea.encrypt(encrypted_M[i*8 +j ], public_key, m_vec);
    }
  }
  std::cout << "Encrypted finished" << std::endl;
    std::ifstream skfile;
  skfile.open("sk");
  helib::SecKey secret_key = helib::SecKey::readFrom(skfile,context);
  skfile.close();
    std::vector<long> decrypted_result;
    helib::CtPtrs_vectorCt result_wrapper(encrypted_M);
    helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
    std::cout << "encrypted_m:" <<std::hex<< decrypted_result.back()<<std::endl;
  // int sendMessageSize = 16 * 3;

  // std::ofstream ciphertext;
  // std::ofstream ciphertext1;
  // ciphertext.open("ciphertext.json");
  // ciphertext1.open("ciphertext1.json");
  // encrypted[0][0].writeToJSON(ciphertext);
  // encrypted[0][2].writeToJSON(ciphertext1);
  // ciphertext.close();
  // ciphertext1.close();

  int receivedMessageBitSize = bitSize;
  int round = 63;
  std::vector<std::vector<helib::Ctxt>> padMessage;
  FHSHA256 hash(public_key);
  hash.FHsha256_pad(padMessage, encrypted_M, receivedMessageBitSize);
  int elementSize = padMessage.size();
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

  hash.FHsha256_update(padMessage, elementSize, round);

  // uint32_t roundState[8];
  // uint32_t lastState[8];
  uint32_t finalState[8];
  // finalState[0]=0xee9feb9f;
  // finalState[1]=0x49906b2b;
  // finalState[2]=0x792b5e5;
  // finalState[3]=0x2eeab7cf;
  // finalState[4]=0x34cb49b;
  // finalState[5]=0xe19d9e05;
  // finalState[6]=0xbf51ca79;
  // finalState[7]=0x9087d275;
  // std::ifstream skfile;
  // skfile.open("sk");
  // helib::SecKey secret_key = helib::SecKey::readFrom(skfile,context);
  // skfile.close();
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
  char messageCheck[128];
  memcpy(messageCheck, buf,64);
  std::cout << "Compute message hash using SHA256" << std::endl;
  
  SHA256 sha;
  sha.update(messageCheck);
  uint8_t * digest = sha.digest();

  std::cout << "hash:"<<SHA256::toString(digest) << std::endl;

}
 