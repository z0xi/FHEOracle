/* hold.h
2021-12-01*/

#include "holder.h"
#include "string.h"
#include <helib/helib.h>
#include <helib/binaryArith.h>
#include <helib/intraSlot.h>

HOLDER::HOLDER(){    
};

void 
HOLDER::keygen(){
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
  // Public key management.
  // Set the secret key (upcast: SecKey is a subclass of PubKey).
  helib::PubKey& pubKey = secret_key;

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
  pubKey.writeTo(pkfile);
  pkfile.close();
}

uint32_t  
rotr(uint32_t x, uint32_t n) {
	return (x >> n) | (x << (32 - n));
}

uint32_t 
sig0(uint32_t x) {
	return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

uint32_t 
sig1(uint32_t x) {
	return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

void  
HOLDER::wtExpand(uint32_t *output , uint8_t *input){
  for (uint8_t i = 0, j = 0; i < 16; i++, j += 4) { // Split data in 32 bit blocks for the 16 first words
		output[i] = (input[j] << 24) | (input[j + 1] << 16) | (input[j + 2] << 8) | (input[j + 3]);
	}

	for (uint8_t k = 16 ; k < 64; k++) { // Remaining 48 blocks
		output[k] =  sig1(output[k - 2]) + output[k - 7] + sig0(output[k - 15]) + output[k - 16];
	}
  std::cout << "...W table created..." << std::endl;
}

uint8_t* 
HOLDER::messagePad(long& elementSize, uint32_t m_blocklen, uint8_t *input){

  uint64_t i = m_blocklen;
  int lastBlockLen = m_blocklen - (m_blocklen / 64) * 64;
  int outputLen;
  uint64_t zeroBlockEnd;
  if(lastBlockLen < 56){
    outputLen = m_blocklen + 64 - lastBlockLen;
  }
  else{
    outputLen = m_blocklen + 64 - lastBlockLen + 64;
  }
  zeroBlockEnd = outputLen - 8;

  uint8_t *output = new uint8_t[outputLen * 8];
  memcpy(output, input, m_blocklen);
	output[i++] = 0x80; // Append a bit 1
	while (i < zeroBlockEnd) {
		output[i++] = 0x00; // Pad with zeros
	}

	uint64_t m_bitlen = m_blocklen * 8;
	output[outputLen - 1] = m_bitlen;
	output[outputLen - 2] = m_bitlen >> 8;
	output[outputLen - 3] = m_bitlen >> 16;
	output[outputLen - 4] = m_bitlen >> 24;
	output[outputLen - 5] = m_bitlen >> 32;
	output[outputLen - 6] = m_bitlen >> 40;
	output[outputLen - 7] = m_bitlen >> 48;
	output[outputLen - 8] = m_bitlen >> 56;
  elementSize = outputLen / 4;
  std::cout << "...Message pad finished..." << std::endl;
  return output;
}

void
HOLDER::bgvEncryptBitWise(std::vector<helib::Ctxt>& encrypted_M, const helib::PubKey& public_key, uint8_t *buf, long bitSize){

    // Get the EncryptedArray of the context.
    const helib::Context& context =  public_key.getContext();
    const helib::EncryptedArray& ea = context.getEA();

    // // Build the unpack slot encoding.
    std::vector<helib::zzX> unpackSlotEncoding;
    buildUnpackSlotEncoding(unpackSlotEncoding, ea);
    helib::Ctxt scratch(public_key);

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
}

void
HOLDER::bgvEncryptElementWise(std::vector<std::vector<helib::Ctxt>>& encrypted_M, const helib::PubKey& public_key, uint32_t *message, long elementIndex){

    // Get the EncryptedArray of the context.
    const helib::Context& context =  public_key.getContext();
    const helib::EncryptedArray& ea = context.getEA();

    // // Build the unpack slot encoding.
    std::vector<helib::zzX> unpackSlotEncoding;
    buildUnpackSlotEncoding(unpackSlotEncoding, ea);

    // Encrypt 4Bytes in each cycle.
    for( int j = 0; j < 64; j++){
        for (int i = 0; i < 32; ++i) {
            std::vector<long> m_vec(ea.size());
                for (auto& slot : m_vec)
                    slot = (message[j] >> i) & 1;
            ea.encrypt(encrypted_M[elementIndex * 64 + j][i], public_key, m_vec);
        }
    }
};