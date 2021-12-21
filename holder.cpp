/* hold.h
2021-12-20*/
#include <iostream>
#include "holder.h"
#include "string.h"
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

HOLDER::HOLDER(){    
};

void 
HOLDER::keygen(){
    //generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    //export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);
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
HOLDER::bgvEncryptElementWise(TFheGateBootstrappingSecretKeySet* key, const TFheGateBootstrappingParameterSet* params, uint32_t *message, long elementIndex){

  for(int i = 0;i < 64; i++){
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(32, params);
    for (int j=0; j<32; j++) {
        bootsSymEncrypt(&ciphertext1[j], (message[i]>>j)&1, key);
    }
    char tmp[20];
    std::sprintf(tmp,"./EM/C_%ld_%d",elementIndex, i);
    FILE* cloud_data = fopen(tmp,"wb");
    for (int j=0; j<32; j++) 
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext1[j], params);
    fclose(cloud_data);
  }
};
