#include <iostream>
#include <assert.h>
#include <string.h>
#include "FHsha256.h"

#include <helib/helib.h>
#include <helib/binaryArith.h>
#include <helib/intraSlot.h>

void keygen(){
  long p = 2;
  long m = 4095;
  long r = 1;
  long bits = 700;
  // long bits = 32;
  long c = 2;
  std::vector<long> mvec = {7, 5, 9, 13};
  std::vector<long> gens = {2341, 3277, 911};
  std::vector<long> ords = {6, 4, 6};
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


  std::cout << "Creating secret key..." << std::endl;
  // Create a secret key associated with the context.
  helib::SecKey secret_key(context);
  // Generate the secret key.
  secret_key.GenSecKey();

  // Generate bootstrapping data.
  secret_key.genRecryptData();
  // Public key management.
  // Set the secret key (upcast: SecKey is a subclass of PubKey).
   helib::PubKey& public_key = secret_key;

  // 以写模式打开文件
  std::ofstream con;
  con.open("context.json");
  context.writeToJSON(con);
  con.close();

  // 以写模式打开文件
  std::ofstream skfile;
  skfile.open("sk.json");
  secret_key.writeToJSON(skfile);
  skfile.close();

    // 以写模式打开文件
  std::ofstream pkfile;
  pkfile.open("pk.json");
  public_key.writeToJSON(pkfile);
  pkfile.close();
}

int main (void) {

  keygen();
 
  std::ifstream con,pkfile;                              
  con.open("context.json");
  helib::Context context =  helib::Context::readFromJSON(con);
  pkfile.open("pk.json");
  helib::PubKey public_key = helib::PubKey::readFromJSON(pkfile,context);
  pkfile.close();
  con.close();
  // Get the EncryptedArray of the context.
  const helib::EncryptedArray& ea = context.getEA();

  // // Build the unpack slot encoding.
  std::vector<helib::zzX> unpackSlotEncoding;
  buildUnpackSlotEncoding(unpackSlotEncoding, ea);
  // // Get the number of slot (phi(m)).
  long nslots = ea.size();
  std::cout << "Number of slots: " << nslots << std::endl;
  
  uint8_t buf[64] = {0x1,0x2,0x3,0x4,0x5,0x6, 0x7,0x8, 
  0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
   0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8, 
   0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
   0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
   0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
   0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
   0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8};

  long bitSize = 32;
  // long outSize = 2 * bitSize;
  long message[16];
  for(int i = 0; i < 16; i++){
    memcpy(&message[i],&buf[ i*4 ],4);
  }

  std::cout << "Pre-encryption data:" << std::endl;
  std::cout << "message = " << message << std::endl;

  // Use a scratch ciphertext to populate vectors.
  // 16 vector and content is scratch
  helib::Ctxt scratch(public_key);
  std::vector<std::vector<helib::Ctxt>> encrypted(16 ,std::vector<helib::Ctxt>(bitSize, scratch));


  // Encrypt 4Bytes in each cycle.
  for (long i = 0; i < bitSize; ++i) {
    std::vector<std::vector<long>> m_vec(16,std::vector<long>(ea.size()));
    for( int j = 0; j < 16; j++){
          for (auto& slot : m_vec[j])
            slot = (message[j] >> i) & 1;
    }
    for (int k = 0 ;k < 16; k++)
      ea.encrypt(encrypted[k][i], public_key, m_vec[k]);
  }
  
  // std::ofstream ciphertext;
  // std::ofstream ciphertext1;
  // ciphertext.open("ciphertext.json");
  // ciphertext1.open("ciphertext1.json");
  // encrypted[0][0].writeToJSON(ciphertext);
  // encrypted[0][2].writeToJSON(ciphertext1);
  // ciphertext.close();
  // ciphertext1.close();

  // std::ifstream skfile;
  // skfile.open("sk.json");
  // helib::SecKey secret_key = helib::SecKey::readFromJSON(skfile,context);
  // skfile.close();
  // std::vector<long> decrypted_result;
  // helib::CtPtrs_vectorCt result_wrapper(encrypted[1]);
  // helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);

  // std::cout << "answer = " << decrypted_result[0] << std::endl;
  // std::cout << "answer = " << decrypted_result[1] << std::endl;


  FHSHA256 hash(public_key);
  hash.FHsha256_H0_init();
  // hash.FHsha256_Wt_init(encrypted);
  // hash.FHsha256_Wt_create(16);
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


  hash.FHsha256_update(encrypted, 16, 5);

  // std::ifstream skfile;
  // skfile.open("sk.json");
  // helib::SecKey secret_key = helib::SecKey::readFromJSON(skfile,context);
  // skfile.close();
  // for(int i = 0;i < 8; i++){
  //   std::vector<long> decrypted_result;
  //   helib::CtPtrs_vectorCt result_wrapper(hash.state[i]);
  //   helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  //   std::cout << "hash " << i << " : "<<std::hex<< decrypted_result[0] << std::endl;
  // }
  // FHsha256_update(&hash, encrypted, 16);
  // sha256_final(&hash, buf);

  // for(int i =0;i < 32;i++) 
  //   printf("%x",buf[i]);
}
 