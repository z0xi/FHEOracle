#include <iostream>

#include <helib/helib.h>
#include <helib/binaryArith.h>
#include <helib/intraSlot.h>

#include <sys/timeb.h>
#include <ctime>
#include <climits>

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

int main(int argc, char* argv[])
{
  struct timeb startTime , endTime;
  // Plaintext prime modulus.
  long p = 2;
  // Cyclotomic polynomial - defines phi(m).
  long m = 4095;
  // Hensel lifting (default = 1).
  long r = 1;
  // Number of bits of the modulus chain.
  long bits = 500;
  // Number of columns of Key-Switching matrix (typically 2 or 3).
  long c = 2;
  // Factorisation of m required for bootstrapping.
  std::vector<long> mvec = {7, 5, 9, 13};
  // Generating set of Zm* group.
  std::vector<long> gens = {2341, 3277, 911};
  // Orders of the previous generators.
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

  // Print the context.
  context.printout();
  std::cout << std::endl;

  // Print the security level.
  std::cout << "Security: " << context.securityLevel() << std::endl;

  // Secret key management.
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
  const helib::PubKey& public_key = secret_key;

  // Get the EncryptedArray of the context.
  const helib::EncryptedArray& ea = context.getEA();

  // Build the unpack slot encoding.
  std::vector<helib::zzX> unpackSlotEncoding;
  buildUnpackSlotEncoding(unpackSlotEncoding, ea);

  // Get the number of slot (phi(m)).
  long nslots = ea.size();
  std::cout << "Number of slots: " << nslots << std::endl;

  // Generate three random binary numbers a, b, c.
  // Encrypt them under BGV.
  // Calculate a * b + c with HElib's binary arithmetic functions, then decrypt
  // the result.
  // Next, calculate a + b + c with HElib's binary arithmetic functions, then
  // decrypt the result.
  // Finally, calculate popcnt(a) with HElib's binary arithmetic functions,
  // then decrypt the result.  Note that popcnt, also known as hamming weight
  // or bit summation, returns the count of non-zero bits.

  // Each bit of the binary number is encoded into a single ciphertext. Thus
  // for a 16 bit binary number, we will represent this as an array of 16
  // unique ciphertexts.
  // i.e. b0 = [0] [0] [0] ... [0] [0] [0]        ciphertext for bit 0
  //      b1 = [1] [1] [1] ... [1] [1] [1]        ciphertext for bit 1
  //      b2 = [1] [1] [1] ... [1] [1] [1]        ciphertext for bit 2
  // These 3 ciphertexts represent the 3-bit binary number 110b = 6

  // Note: several numbers can be encoded across the slots of each ciphertext
  // which would result in several parallel slot-wise operations.
  // For simplicity we place the same data into each slot of each ciphertext,
  // printing out only the back of each vector.
  // NB: fifteenOrLess4Four max is 15 bits. Later in the code we pop the MSB.
  long bitSize = 32;
  long a_data = NTL::RandomBits_long(bitSize);
  long b_data = NTL::RandomBits_long(bitSize);
  long c_data = NTL::RandomBits_long(bitSize);

  std::cout << "Pre-encryption data:" << std::endl;
  std::cout << "a = " << std::hex << a_data << std::endl;
  std::cout << "b = " << std::hex << b_data << std::endl;
  std::cout << "c = " << std::hex << c_data << std::endl;

  ftime(&startTime);
  // Use a scratch ciphertext to populate vectors.
  helib::Ctxt scratch(public_key);
  std::vector<helib::Ctxt> encrypted_a(bitSize, scratch);
  std::vector<helib::Ctxt> encrypted_b(bitSize, scratch);
  std::vector<helib::Ctxt> encrypted_c(bitSize, scratch);
  // Encrypt the data in binary representation.
  for (long i = 0; i < bitSize; ++i) {
    std::vector<long> a_vec(ea.size());
    std::vector<long> b_vec(ea.size());
    std::vector<long> c_vec(ea.size());
    // Extract the i'th bit of a,b,c.
    for (auto& slot : a_vec)
      slot = (a_data >> i) & 1;
    for (auto& slot : b_vec)
      slot = (b_data >> i) & 1;
    for (auto& slot : c_vec)
      slot = (c_data >> i) & 1;
    ea.encrypt(encrypted_a[i], public_key, a_vec);
    ea.encrypt(encrypted_b[i], public_key, b_vec);
    ea.encrypt(encrypted_c[i], public_key, c_vec);
  }
  ftime(&endTime);
  std::cout << "加密3*32Bits耗时：" << std::dec <<(endTime.time-startTime.time)*1000 + (endTime.millitm - startTime.millitm) << "毫秒\n" << std::endl;

  // Although in general binary numbers are represented here as
  // std::vector<helib::Ctxt> the binaryArith APIs for HElib use the PtrVector
  // wrappers instead, e.g. helib::CtPtrs_vectorCt. These are nothing more than
  // thin wrapper classes to standardise access to different vector types, such
  // as NTL::Vec and std::vector. They do not take ownership of the underlying
  // object but merely provide access to it.
  //
  // helib::CtPtrMat_vectorCt is a wrapper for
  // std::vector<std::vector<helib::Ctxt>>, used for representing a list of
  // encrypted binary numbers.

  // Perform the multiplication first and put it in encrypted_product.

  std::vector<long> decrypted_result;
  ftime(&startTime);
  std::vector<helib::Ctxt> encrypted_result;
  helib::CtPtrs_vectorCt result_wrapper(encrypted_result);
  std::vector<std::vector<helib::Ctxt>> summands = {encrypted_a,
                                                    encrypted_b,
                                                    encrypted_c};
  helib::CtPtrMat_vectorCt summands_wrapper(summands);
  helib::addManyNumbers(
      result_wrapper,
      summands_wrapper,
      0,                    // sizeLimit=0 means use as many bits as needed.
      &unpackSlotEncoding); // Information needed for bootstrapping.
  ftime(&endTime);  
  std::cout << "a + b + c耗时：" << std::dec <<(endTime.time-startTime.time)*1000 + (endTime.millitm - startTime.millitm) << "毫秒" << std::endl;
  
  ftime(&startTime);
  for(int i = 0; i < 32; i++){
    public_key.thinReCrypt(encrypted_result[i]);
  }
  ftime(&endTime);  
  std::cout << "thin bootstrap 32Bits耗时：" << std::dec << (endTime.time-startTime.time)*1000 + (endTime.millitm - startTime.millitm) << "毫秒" << std::endl;

  decrypted_result.clear();

  ftime(&startTime);
  helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  ftime(&endTime);  
  std::cout << "解密32Bits耗时：" << std::dec << (endTime.time-startTime.time)*1000 + (endTime.millitm - startTime.millitm) << "毫秒" << std::endl;
  std::cout << "a + b + c = " <<  std::hex<< decrypted_result.back() <<  "\n"<<std::endl;


  decrypted_result.clear();
  ftime(&startTime);
  std::vector<helib::Ctxt> encrypted_leftshift(32,scratch);
  helib::CtPtrs_vectorCt leftshift_wrapper(encrypted_leftshift);
  helib::leftBitwiseShift(leftshift_wrapper,  helib::CtPtrs_vectorCt(encrypted_a), 3);
  ftime(&endTime); 
  helib::decryptBinaryNums(decrypted_result, leftshift_wrapper, secret_key, ea);
  std::cout << "32Bits左移3位耗时：" << std::dec <<(endTime.time-startTime.time)*1000 + (endTime.millitm - startTime.millitm) << "毫秒" << std::endl;
  std::cout << "a << 3 = " << std::hex<< decrypted_result.back() <<  "\n"<<std::endl;

  decrypted_result.clear();
  ftime(&startTime);
  std::vector<helib::Ctxt> encrypted_rightshift(32,scratch);
  helib::CtPtrs_vectorCt rightshift_wrapper(encrypted_rightshift);
  rightBitwiseShift(rightshift_wrapper,  helib::CtPtrs_vectorCt(encrypted_a), 3);
  ftime(&endTime); 
  helib::decryptBinaryNums(decrypted_result, rightshift_wrapper, secret_key, ea);
  std::cout << "32Bits右移3位耗时：" << std::dec <<(endTime.time-startTime.time)*1000 + (endTime.millitm - startTime.millitm) << "毫秒" << std::endl;
  std::cout << "a >> 3 = " << std::hex<< decrypted_result.back() <<  "\n"<<std::endl;

  decrypted_result.clear();
  ftime(&startTime);
  std::vector<helib::Ctxt> encrypted_xor(32,scratch);
  helib::CtPtrs_vectorCt xor_wrapper(encrypted_xor);
  helib::bitwiseXOR(xor_wrapper, helib::CtPtrs_vectorCt(encrypted_a), helib::CtPtrs_vectorCt(encrypted_b));
  ftime(&endTime); 
  helib::decryptBinaryNums(decrypted_result, xor_wrapper, secret_key, ea);
  std::cout << "a xor b 耗时：" << std::dec <<(endTime.time-startTime.time)*1000 + (endTime.millitm - startTime.millitm) << "毫秒" << std::endl;
  std::cout << "a xor b = " <<  std::hex<< decrypted_result.back() <<  "\n"<<std::endl;

  decrypted_result.clear();
  ftime(&startTime);
  std::vector<helib::Ctxt> encrypted_not(32,scratch);
  helib::CtPtrs_vectorCt not_wrapper(encrypted_not);
  helib::bitwiseNot(not_wrapper, helib::CtPtrs_vectorCt(encrypted_a));
  ftime(&endTime); 
  helib::decryptBinaryNums(decrypted_result, not_wrapper, secret_key, ea);
  std::cout << "a取反耗时：" << std::dec <<(endTime.time-startTime.time)*1000 + (endTime.millitm - startTime.millitm) << "毫秒" << std::endl;
  std::cout << "~a = " << std::hex<< decrypted_result.back() << "\n"<<std::endl;

  decrypted_result.clear();
  ftime(&startTime);
  std::vector<helib::Ctxt> encrypted_addtwo;
  helib::CtPtrs_vectorCt addtwo_wrapper(encrypted_addtwo);
  helib::addTwoNumbers(
      addtwo_wrapper,
      helib::CtPtrs_vectorCt(encrypted_a),
      helib::CtPtrs_vectorCt(encrypted_b),
      0,                    // sizeLimit=0 means use as many bits as needed.
      &unpackSlotEncoding); // Information needed for bootstrapping.
  ftime(&endTime);  
  std::cout << "a + b耗时：" << std::dec<< (endTime.time-startTime.time)*1000 + (endTime.millitm - startTime.millitm) << "毫秒" << std::endl;
  helib::decryptBinaryNums(decrypted_result, addtwo_wrapper, secret_key, ea);
  std::cout << "a + b  = " <<  std::hex<< decrypted_result.back() <<  "\n"<<std::endl;

  ftime(&startTime);
  for(int i = 0; i < 32; i++){
    public_key.reCrypt(encrypted_result[i]);
  }
  ftime(&endTime);  
  std::cout << "bootstrap 32Bits耗时：" << std::dec << (endTime.time-startTime.time)*1000 + (endTime.millitm - startTime.millitm) << "毫秒" << std::endl;


  // encrypted_result.resize(4lu, scratch);
  // decrypted_result.clear();
  // encrypted_a.pop_back(); // drop the MSB since we only support up to 15 bits.
  // ftime(&startTime);
  // helib::fifteenOrLess4Four(result_wrapper,
  //                           helib::CtPtrs_vectorCt(encrypted_a));
  // ftime(&endTime); 
  // std::cout << "计算32Bits中1个数耗时：" << int((endTime.time-startTime.time)*1000 + (endTime.millitm - startTime.millitm)) << "毫秒" << std::endl;
  // helib::decryptBinaryNums(decrypted_result, result_wrapper, secret_key, ea);
  // std::cout << "popcnt(a) = " << decrypted_result.back() << std::endl;

  return 0;
}

