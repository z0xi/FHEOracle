/* Crypto/Sha256.c -- SHA-256 Hash
2021-10-28*/

#include "FHsha256.h"
#include "string.h"
#include <helib/helib.h>
#include <helib/binaryArith.h>
#include <helib/intraSlot.h>


std::vector<helib::zzX> unpackSlotEncoding;

uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
uint32_t H0[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};


FHSHA256::FHSHA256(const helib::PubKey& newPubKey) : public_key(newPubKey){
  }


void rotateRightBitwiseShift(helib::CtPtrs& output, const helib::CtPtrs& input, const long shamt)
{
  // helib::assertEq(shamt >= 0, "Shift amount must be positive.");
  // helib::assertEq(output.size(),
  //          input.size(),
  //          "output and input must have the same size.");
 
  for (long i = 0; i < output.size() - shamt; ++i)
    *output[i] = *input[i + shamt];
  for (long i = output.size() - shamt, j = 0; i < output.size(); ++i, ++j)
    *output[i] = *input[j];
}

void rightBitwiseShift(helib::CtPtrs& output, const helib::CtPtrs& input, const long shamt)
{
  // helib::assertEq(shamt >= 0, "Shift amount must be positive.");
  // helib::assertEq(output.size(),
  //          input.size(),
  //          "output and input must have the same size.");
 
  for (long i = 0; i < output.size() - shamt; ++i)
    *output[i] = *input[i + shamt];
  for (long i = output.size() - shamt; i < output.size(); ++i)
    output[i]->clear();
}

void
FHSHA256::FHsha256_H0_init()
{
    //H0 init
    helib::Ctxt scratch(public_key);
    std::vector<std::vector<helib::Ctxt> >  encrypted(8 ,std::vector<helib::Ctxt>(32, scratch));
    const helib::Context& context = public_key.getContext();

    const helib::EncryptedArray& ea = context.getEA();
    buildUnpackSlotEncoding(unpackSlotEncoding, ea);

    for (long i = 0; i < 32; ++i) {
        std::vector<std::vector<long>> m_vec(8,std::vector<long>(ea.size()));
        // Extract the i'th bit of a,b,c.
        for( int j = 0; j < 8; j++){
            for (auto& slot : m_vec[j])
                slot = (H0[j] >> i) & 1;
        }
        for (int k = 0 ;k < 8; k++)
            ea.encrypt(encrypted[k][i], public_key, m_vec[k]);
    }
    for( int s = 0;s < 8 ;s++){
        state.push_back(encrypted[s]);
    }
  std::cout<<"H0"<<" init"<<" finished\n";
}


void 
FHSHA256::FHsha256_Wt_init(std::vector<std::vector<helib::Ctxt> > data){
  // Init 
  Wt_Encrypted.clear();
  // trans to Big ending
  for(int i = 0; i < 16; i++){
    std::vector<helib::Ctxt> tempCtxt;
    tempCtxt.push_back(data[i][24]);
    tempCtxt.push_back(data[i][25]);
    tempCtxt.push_back(data[i][26]);
    tempCtxt.push_back(data[i][27]);
    tempCtxt.push_back(data[i][28]);
    tempCtxt.push_back(data[i][29]);
    tempCtxt.push_back(data[i][30]);
    tempCtxt.push_back(data[i][31]);

    tempCtxt.push_back(data[i][16]);
    tempCtxt.push_back(data[i][17]);
    tempCtxt.push_back(data[i][18]);
    tempCtxt.push_back(data[i][19]);
    tempCtxt.push_back(data[i][20]);
    tempCtxt.push_back(data[i][21]);
    tempCtxt.push_back(data[i][22]);
    tempCtxt.push_back(data[i][23]);

    tempCtxt.push_back(data[i][8]);
    tempCtxt.push_back(data[i][9]);
    tempCtxt.push_back(data[i][10]);
    tempCtxt.push_back(data[i][11]);
    tempCtxt.push_back(data[i][12]);
    tempCtxt.push_back(data[i][13]);
    tempCtxt.push_back(data[i][14]);
    tempCtxt.push_back(data[i][15]);

    tempCtxt.push_back(data[i][0]);
    tempCtxt.push_back(data[i][1]);
    tempCtxt.push_back(data[i][2]);
    tempCtxt.push_back(data[i][3]);
    tempCtxt.push_back(data[i][4]);
    tempCtxt.push_back(data[i][5]);
    tempCtxt.push_back(data[i][6]);
    tempCtxt.push_back(data[i][7]);

    Wt_Encrypted.push_back(tempCtxt);
  }
  // Wt_Encrypted.insert(Wt_Encrypted.begin(), temp.begin(), temp.end());
  std::cout<<"W0 - W15"<<" init"<<" finished\n";
}

void 
FHSHA256::FHsha256_Wt_create(int t){
  if (t < 16){
    return;
  }
  helib::Ctxt scratch(public_key);
  std::vector<helib::Ctxt> w(32, scratch);;
  std::vector<helib::Ctxt> temp1(32, scratch);
  std::vector<helib::Ctxt> temp2(32, scratch);
  std::vector<helib::Ctxt> temp3(32, scratch);
  std::vector<helib::Ctxt> xima0(32, scratch);
  std::vector<helib::Ctxt> xima1(32, scratch);
  std::vector<helib::Ctxt> temp(32, scratch);

  helib::CtPtrs_vectorCt temp1_wrapper(temp1);
  helib::CtPtrs_vectorCt temp2_wrapper(temp2);  
  helib::CtPtrs_vectorCt temp3_wrapper(temp3);  
  helib::CtPtrs_vectorCt xima0_wrapper(xima0);  
  helib::CtPtrs_vectorCt xima1_wrapper(xima1);  
  helib::CtPtrs_vectorCt temp_wrapper(temp);

  rotateRightBitwiseShift(temp1_wrapper,  helib::CtPtrs_vectorCt(Wt_Encrypted[t-15]), 7);
  rotateRightBitwiseShift(temp2_wrapper,  helib::CtPtrs_vectorCt(Wt_Encrypted[t-15]), 18);
  rightBitwiseShift(temp3_wrapper,  helib::CtPtrs_vectorCt(Wt_Encrypted[t-15]), 3);
  bitwiseXOR(temp_wrapper,temp1_wrapper,temp2_wrapper);
  bitwiseXOR(xima0_wrapper,temp_wrapper,temp3_wrapper);

  rotateRightBitwiseShift(temp1_wrapper, helib::CtPtrs_vectorCt(Wt_Encrypted[t-2]), 17);
  rotateRightBitwiseShift(temp2_wrapper, helib::CtPtrs_vectorCt(Wt_Encrypted[t-2]), 19);
  rightBitwiseShift(temp3_wrapper, helib::CtPtrs_vectorCt(Wt_Encrypted[t-2]), 10);
  bitwiseXOR(temp_wrapper,temp1_wrapper,temp2_wrapper);
  bitwiseXOR(xima1_wrapper,temp_wrapper,temp3_wrapper);

  std::vector<std::vector<helib::Ctxt>> summands = {xima0,
                                                    xima1,
                                                    Wt_Encrypted[t-7],
                                                    Wt_Encrypted[t-16]};
  helib::CtPtrMat_vectorCt summands_wrapper(summands);
  helib::CtPtrs_vectorCt Wt_wrapper(w);
  helib::addManyNumbers(
    Wt_wrapper,
    summands_wrapper,
    32,                    // sizeLimit=0 means use as many bits as needed.
    &unpackSlotEncoding); // Information needed for bootstrapping.
  for( int i = 0;i < 32; i++){
      // std::cout << "W" << t<< " bit "<< i<< " before thinRecrypt capacity:"<< w[i].bitCapacity() <<std::endl;
      public_key.thinReCrypt(w[i]);
      // std::cout << "W" << t<< " bit "<< i<< " after thinRecrypt capacity:"<< w[i].bitCapacity() <<std::endl;
  }
  Wt_Encrypted.push_back(Wt_wrapper.v);
  std::cout<<"W"<<t<<" generated\n";
}

void 
FHSHA256::FHsha256_Kt_Encrypted(std::vector<helib::Ctxt>&  Kt_Encrypted ,int t){
  const helib::Context& context = public_key.getContext();
  const helib::EncryptedArray& ea = context.getEA();

  for (long i = 0; i < 32; ++i) {
    std::vector<long> Kt_vec(ea.size());
    for (auto& slot : Kt_vec)
      slot = (K[t] >> i) & 1;
    ea.encrypt(Kt_Encrypted[i], public_key, Kt_vec);
  }
  std::cout<<"K"<<t<<" encrypted"<<" finished\n";
  

  // std::ifstream skfile;
  // skfile.open("sk");
  // helib::SecKey secret_key = helib::SecKey::readFrom(skfile,context);
  // skfile.close();
  // std::vector<long> decrypted_result;
  // helib::CtPtrs_vectorCt result_wrapper(Kt_Encrypted);
  // helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  // std::cout << "K"<<t <<" = " <<std::hex<< decrypted_result[0] << std::endl;
}

void
FHSHA256::FHsha256_Ch(std::vector<helib::Ctxt>& ch, std::vector<std::vector<helib::Ctxt> > tempState){
  helib::Ctxt scratch(public_key);
  std::vector<helib::Ctxt> temp1_ctxt(32, scratch);
  std::vector<helib::Ctxt> temp2_ctxt(32, scratch);
  std::vector<helib::Ctxt> temp_ctxt(32, scratch);
  helib::CtPtrs_vectorCt e_wrapper(tempState[4]);
  helib::CtPtrs_vectorCt f_wrapper(tempState[5]);  
  helib::CtPtrs_vectorCt g_wrapper(tempState[6]);
  helib::CtPtrs_vectorCt temp1_wrapper(temp1_ctxt);
  helib::CtPtrs_vectorCt temp2_wrapper(temp2_ctxt);
  helib::CtPtrs_vectorCt temp_wrapper(temp_ctxt);
  
  helib::bitwiseAnd(temp1_wrapper, e_wrapper, f_wrapper);
  helib::bitwiseNot(temp2_wrapper, e_wrapper);
  helib::bitwiseAnd(temp_wrapper, temp2_wrapper, g_wrapper);
  helib::bitwiseXOR(temp2_wrapper, temp_wrapper, temp1_wrapper);

  for(int i = 0;i < 32; i++){
    ch.push_back(temp2_wrapper.v[i]);
  }
 
  // const helib::Context& context =  public_key.getContext();
  // std::ifstream skfile;
  // skfile.open("sk");
  // helib::SecKey secret_key = helib::SecKey::readFrom(skfile,context);
  // skfile.close();
  // std::vector<long> decrypted_result;
  // const helib::EncryptedArray& ea = context.getEA();
  // helib::CtPtrs_vectorCt result_wrapper(ch);
  // helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  // std::cout << "ch = " << std::hex<<decrypted_result[0] << std::endl;
};

void 
FHSHA256::FHsha256_Ma(std::vector<helib::Ctxt>& Ma, std::vector<std::vector<helib::Ctxt> > tempState){
  helib::Ctxt scratch(public_key);
  std::vector<helib::Ctxt> temp1_ctxt(32, scratch);
  std::vector<helib::Ctxt> temp2_ctxt(32, scratch);
  std::vector<helib::Ctxt> temp_ctxt(32, scratch);
  helib::CtPtrs_vectorCt a_wrapper(tempState[0]);
  helib::CtPtrs_vectorCt b_wrapper(tempState[1]);  
  helib::CtPtrs_vectorCt c_wrapper(tempState[2]);
  helib::CtPtrs_vectorCt temp1_wrapper(temp1_ctxt);
  helib::CtPtrs_vectorCt temp2_wrapper(temp2_ctxt);
  helib::CtPtrs_vectorCt temp_wrapper(temp_ctxt);

  helib::bitwiseAnd(temp1_wrapper, a_wrapper, b_wrapper);
  helib::bitwiseAnd(temp2_wrapper, a_wrapper, c_wrapper);
  helib::bitwiseXOR(temp_wrapper, temp1_wrapper, temp2_wrapper);
  helib::bitwiseAnd(temp1_wrapper, b_wrapper, c_wrapper);
  helib::bitwiseXOR(temp2_wrapper, temp_wrapper, temp1_wrapper);

  for(int i = 0;i < 32; i++){
    Ma.push_back(temp2_wrapper.v[i]);
  }

  // const helib::Context& context =  public_key.getContext();
  // std::ifstream skfile;
  // skfile.open("sk");
  // helib::SecKey secret_key = helib::SecKey::readFrom(skfile,context);
  // skfile.close();
  // std::vector<long> decrypted_result;
  // const helib::EncryptedArray& ea = context.getEA();
  // helib::CtPtrs_vectorCt result_wrapper(Ma);
  // helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  // std::cout << "Ma = " <<std::hex<< decrypted_result[0] << std::endl;
};

void 
FHSHA256::FHsha256_sigma0(std::vector<helib::Ctxt>& sigma0, std::vector<std::vector<helib::Ctxt> > tempState){
  helib::Ctxt scratch(public_key);
  std::vector<helib::Ctxt> temp1_ctxt(32, scratch);
  std::vector<helib::Ctxt> temp2_ctxt(32, scratch);
  std::vector<helib::Ctxt> temp_ctxt(32, scratch);
  helib::CtPtrs_vectorCt a_wrapper(tempState[0]);
  helib::CtPtrs_vectorCt temp1_wrapper(temp1_ctxt);
  helib::CtPtrs_vectorCt temp2_wrapper(temp2_ctxt);
  helib::CtPtrs_vectorCt temp_wrapper(temp_ctxt);

  rotateRightBitwiseShift(temp1_wrapper, a_wrapper, 2);
  rotateRightBitwiseShift(temp2_wrapper, a_wrapper, 13);
  helib::bitwiseXOR(temp_wrapper, temp1_wrapper, temp2_wrapper);
  rotateRightBitwiseShift(temp1_wrapper, a_wrapper, 22);
  helib::bitwiseXOR(temp2_wrapper, temp_wrapper, temp1_wrapper);

  for(int i = 0;i < 32; i++){
    sigma0.push_back(temp2_wrapper.v[i]);
  }

  // const helib::Context& context =  public_key.getContext();
  // std::ifstream skfile;
  // skfile.open("sk");
  // helib::SecKey secret_key = helib::SecKey::readFrom(skfile,context);
  // const helib::EncryptedArray& ea = context.getEA();
  // skfile.close();
  // std::vector<long> decrypted_result;
  // helib::CtPtrs_vectorCt result_wrapper(sigma0);
  // helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  // std::cout << "sigma0 = " <<std::hex<< decrypted_result[0] << std::endl;
};

void 
FHSHA256::FHsha256_sigma1(std::vector<helib::Ctxt>& sigma1, std::vector<std::vector<helib::Ctxt> > tempState){
  helib::Ctxt scratch(public_key);
  std::vector<helib::Ctxt> temp1_ctxt(32, scratch);
  std::vector<helib::Ctxt> temp2_ctxt(32, scratch);
  std::vector<helib::Ctxt> temp_ctxt(32, scratch);
  helib::CtPtrs_vectorCt e_wrapper(tempState[4]);
  helib::CtPtrs_vectorCt temp1_wrapper(temp1_ctxt);
  helib::CtPtrs_vectorCt temp2_wrapper(temp2_ctxt);
  helib::CtPtrs_vectorCt temp_wrapper(temp_ctxt);

  rotateRightBitwiseShift(temp1_wrapper, e_wrapper, 6);
  rotateRightBitwiseShift(temp2_wrapper, e_wrapper, 11);
  helib::bitwiseXOR(temp_wrapper, temp1_wrapper, temp2_wrapper);
  rotateRightBitwiseShift(temp1_wrapper, e_wrapper, 25);
  helib::bitwiseXOR(temp2_wrapper, temp_wrapper, temp1_wrapper);

  for(int i = 0;i < 32; i++){
    sigma1.push_back(temp2_wrapper.v[i]);
  }
   
   
  // const helib::Context& context =  public_key.getContext();
  // std::ifstream skfile;
  // skfile.open("sk");
  // helib::SecKey secret_key = helib::SecKey::readFrom(skfile,context);
  // skfile.close();
  // std::vector<long> decrypted_result;
  // const helib::EncryptedArray& ea = context.getEA();
  // helib::CtPtrs_vectorCt result_wrapper(sigma1);
  // helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  // std::cout << "sigma1 = " << std::hex<<decrypted_result[0] << std::endl;
};

void 
FHSHA256::FHsha256_transform(int round, int groupIndex){
  
  helib::Ctxt scratch(public_key);
  const helib::Context& context =  public_key.getContext();
  std::ifstream skfile;
  skfile.open("sk");
  helib::SecKey secret_key = helib::SecKey::readFrom(skfile,context);
  skfile.close();
  const helib::EncryptedArray& ea = context.getEA();

  std::vector<std::vector<helib::Ctxt> > tempState(state);
  int roundNum = 63;
  if(groupIndex == group)
    roundNum = round;
  for( int r = 0; r <= roundNum; r++){
    std::vector<helib::Ctxt> Kt(32,scratch);
    std::vector<helib::Ctxt> ch;
    std::vector<helib::Ctxt> ma;
    std::vector<helib::Ctxt> sigma0;
    std::vector<helib::Ctxt> sigma1;

    FHsha256_Wt_create(r);

    // std::vector<long> wt_result;
    // helib::CtPtrs_vectorCt wt_wrapper(Wt_Encrypted[r]);
    // helib::decryptBinaryNums(wt_result, wt_wrapper, secret_key, ea);
    // std::cout << "W"<< r<<" = " <<std::hex<< wt_result[0] << std::endl;

    FHsha256_Kt_Encrypted(Kt ,r);
    FHsha256_Ch(ch, tempState);
    FHsha256_Ma(ma, tempState);
    FHsha256_sigma0(sigma0, tempState);
    FHsha256_sigma1(sigma1, tempState);
    std::cout<<"ch ma sigma1 sigma0"<<" generated\n";
    std::vector<helib::Ctxt> temp;
    std::vector<helib::Ctxt> temp1;
    std::vector<helib::Ctxt> temp2;
    std::vector<std::vector<helib::Ctxt>> summands = {ch,
                                                    Kt,
                                                    sigma1,
                                                    Wt_Encrypted[r],
                                                    tempState[7]};
    helib::CtPtrMat_vectorCt oneSum(summands);
    helib::CtPtrs_vectorCt oneSum_wrapper(temp);
    helib::addManyNumbers(
      oneSum_wrapper,
      oneSum,
      32,
      &unpackSlotEncoding);

    std::vector<std::vector<helib::Ctxt>> summandA = {temp,
                                                    ma,
                                                    sigma0
                                                    };
    helib::CtPtrMat_vectorCt twoSum(summandA);
    helib::CtPtrs_vectorCt twoSum_wrapper(temp1);
    helib::addManyNumbers(
      twoSum_wrapper,
      twoSum,
      32,
      &unpackSlotEncoding);

    helib::CtPtrs_vectorCt threeSum_wrapper(temp2);
    helib::addTwoNumbers(
      threeSum_wrapper,
      helib::CtPtrs_vectorCt(tempState[3]),
      oneSum_wrapper,
      32,
      &unpackSlotEncoding);

    tempState[7].assign(tempState[6].begin(), tempState[6].end());
    tempState[6].assign(tempState[5].begin(), tempState[5].end());
    tempState[5].assign(tempState[4].begin(), tempState[4].end());
    tempState[4].assign(threeSum_wrapper.v.begin(), threeSum_wrapper.v.end());
    tempState[3].assign(tempState[2].begin(), tempState[2].end());
    tempState[2].assign(tempState[1].begin(), tempState[1].end());
    tempState[1].assign(tempState[0].begin(), tempState[0].end());
    tempState[0].assign(twoSum_wrapper.v.begin(), twoSum_wrapper.v.end());

    std::cout<<"Round "<< r <<" A-H generated\n";

    // std::vector<long> decrypted_result;
    // helib::CtPtrs_vectorCt result_wrapper(tempState[0]);
    // helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
    // std::cout << "Group "<< groupIndex << " Round " << r << " state "<< "0" << " : "<<std::hex<< decrypted_result[0] << std::endl;
    for(int j = 0; j < 32;j++){
      // std::cout << "Group "<< groupIndex << " Round " << r << " state "<< "0 " << "bit "<< j<< " before thinRecrypt capacity:"<< tempState[0][j].bitCapacity() <<std::endl;
      public_key.thinReCrypt(tempState[0][j]);
      // std::cout << "Group "<< groupIndex << " Round " << r << " state "<< "0 " << "bit "<< j<< " after thinRecrypt capacity:"<< tempState[0][j].bitCapacity() <<std::endl;
      // std::cout << "Group "<< groupIndex << " Round " << r << " state "<< "4 " << "bit "<< j<< " before thinRecrypt capacity:"<< tempState[4][j].bitCapacity() <<std::endl;
      public_key.thinReCrypt(tempState[4][j]);
      // std::cout << "Group "<< groupIndex << " Round " << r << " state "<< "4 " << "bit "<< j<< " before thinRecrypt capacity:"<< tempState[4][j].bitCapacity() <<std::endl;
    }
    std::cout << "A E Bootstrap finished"<<std::endl;
  }

  if(roundNum == 63){
    std::vector<std::vector<helib::Ctxt> > tempState_1(state);
    helib::CtPtrs_vectorCt state0_wrapper(state[0]);
    helib::CtPtrs_vectorCt state1_wrapper(state[1]);
    helib::CtPtrs_vectorCt state2_wrapper(state[2]);
    helib::CtPtrs_vectorCt state3_wrapper(state[3]);
    helib::CtPtrs_vectorCt state4_wrapper(state[4]);
    helib::CtPtrs_vectorCt state5_wrapper(state[5]);
    helib::CtPtrs_vectorCt state6_wrapper(state[6]);
    helib::CtPtrs_vectorCt state7_wrapper(state[7]);
    helib::addTwoNumbers(
      state0_wrapper,
      helib::CtPtrs_vectorCt(tempState_1[0]),
      helib::CtPtrs_vectorCt(tempState[0]),
      32,
      &unpackSlotEncoding);
    helib::addTwoNumbers(
      state1_wrapper,
      helib::CtPtrs_vectorCt(tempState_1[1]),
      helib::CtPtrs_vectorCt(tempState[1]),
      32,
      &unpackSlotEncoding);
    helib::addTwoNumbers(
      state2_wrapper,
      helib::CtPtrs_vectorCt(tempState_1[2]),
      helib::CtPtrs_vectorCt(tempState[2]),
      32,
      &unpackSlotEncoding);
    helib::addTwoNumbers(
      state3_wrapper,
      helib::CtPtrs_vectorCt(tempState_1[3]),
      helib::CtPtrs_vectorCt(tempState[3]),
      32,
      &unpackSlotEncoding);
    helib::addTwoNumbers(
      state4_wrapper,
      helib::CtPtrs_vectorCt(tempState_1[4]),
      helib::CtPtrs_vectorCt(tempState[4]),
      32,
      &unpackSlotEncoding);
    helib::addTwoNumbers(
      state5_wrapper,
      helib::CtPtrs_vectorCt(tempState_1[5]),
      helib::CtPtrs_vectorCt(tempState[5]),
      32,
      &unpackSlotEncoding);
    helib::addTwoNumbers(
      state6_wrapper,
      helib::CtPtrs_vectorCt(tempState_1[6]),
      helib::CtPtrs_vectorCt(tempState[6]),
      32,
      &unpackSlotEncoding);
    helib::addTwoNumbers(
      state7_wrapper,
      helib::CtPtrs_vectorCt(tempState_1[7]),
      helib::CtPtrs_vectorCt(tempState[7]),
      32,
      &unpackSlotEncoding);

    std::cout<<"Group "<< groupIndex << " hash generated\n";

    std::vector<long> state_result;
    helib::CtPtrs_vectorCt state_wrapper(state[0]);
    helib::decryptBinaryNums(state_result, state_wrapper, secret_key, ea);
    std::cout<<"Group "<< groupIndex << " hash :" <<std::hex<< state_result[0] << std::endl;

    for(int j = 0; j < 32;j++){
      for( int k = 0; k < 8; k++){
        // std::cout << "Hash state " << k<< " bit "<< j<< " before thinRecrypt capacity:"<< state[k][j].bitCapacity() <<std::endl;
        public_key.thinReCrypt(state[k][j]);
        // std::cout << "Hash state " << k<< " bit "<< j<< " after thinRecrypt capacity:"<< state[k][j].bitCapacity() <<std::endl;
      }
    }
    std::cout << "Hash state Bootstrap finished"<<std::endl;
  }
};

void
FHSHA256::FHsha256_update(std::vector<std::vector<helib::Ctxt> > data, size_t elementSize, int round)
{
  long data_index = 0;
  int count = 0;
  group = elementSize / 16;
  int groupIndex = 1;
  // P.S. 1 elementSize = 32bits
  while (elementSize > 0)
  {
    buffer.push_back(data[data_index]);
    count++;
    data_index++;
    elementSize--;
    if (count == 16)
    {
      count = 0;
      FHsha256_Wt_init(buffer);
      FHsha256_transform(round, groupIndex);
      groupIndex++;
      buffer.clear();
    }
  }
};