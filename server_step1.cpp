#include <stdio.h>
#include <iostream> 
#include <fstream>
#include <sstream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include"cstdlib"

#include<functional>
#define MAX 20000
struct element{     //用来排序的数据结构 
		int data;  // 数据 
		int index;  // 序号 
};
int exec_cmd(std::string cmd, std::string &res){
  if (cmd.size() == 0){  //cmd is empty 
    return -1;
  }
 
  char buffer[1024] = {0};
  std::string result = "";
  FILE *pin = popen(cmd.c_str(), "r");
  if (!pin) { //popen failed 
    return -1;
  }
 
  res.clear();
  while(!feof(pin)){
    if(fgets(buffer, sizeof(buffer), pin) != NULL){
      result += buffer;
    }
  }
 
  res = result;
  return pclose(pin); //-1:pclose failed; else shell ret
}

std::vector<int> GenerateRanNumber(int min,int max,int num)
{
    int rnd;
    std::vector<int> diff;
    std::srand((unsigned)time(0)); //初始化随机数种子
    for(int i = 0 ; i < num ; i++)
    {
        rnd = min+rand()%(max-min+1);
        diff.push_back(rnd);
    }
    return diff;
}
void Adder(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
  LweSample* tmps = new_gate_bootstrapping_ciphertext_array(4, bk->params);

  //initialize the carry to 0
  bootsCONSTANT(&tmps[0], 0, bk);
  bootsCONSTANT(&tmps[1], 0, bk);
  bootsCONSTANT(&tmps[2], 0, bk);
  bootsCONSTANT(&tmps[3], 0, bk);
  //run the elementary comparator gate n times
  for (int i=0; i<nb_bits; i++) {
      bootsXOR(&tmps[1], &a[i], &b[i], bk);
      bootsAND(&tmps[2], &a[i], &b[i], bk);
      bootsXOR(&result[i], &tmps[1], &tmps[0], bk);
      bootsAND(&tmps[3], &tmps[0], &tmps[1], bk);
      bootsOR(&tmps[0], &tmps[2], &tmps[3], bk);
  }
  delete_gate_bootstrapping_ciphertext_array(4, tmps);
}
// void Addition(LweSample* top1, const LweSample* a6, const LweSample* b6, LweSample* lsb_carry1, LweSample* tmp6, const  TFheGateBootstrappingCloudKeySet* bk) {
//     LweSample* temp1=new_gate_bootstrapping_ciphertext_array(1, bk->params);
//     LweSample* temp2=new_gate_bootstrapping_ciphertext_array(1, bk->params);
//     LweSample* temp3=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    
//     bootsXOR(temp1, a6, b6, bk);  //a xor b  
//     bootsXOR(top1,temp1,lsb_carry1,bk);  //a xor b xor ci
//     bootsAND(temp2,temp1,lsb_carry1,bk);   //ci and (a xor b)
//     bootsAND(temp3,a6,b6,bk);             // a and b 
//     bootsOR(tmp6,temp2,temp3,bk);       // a&b + ci*(a xor b)
//     bootsCOPY(lsb_carry1,tmp6,bk);


// }
// void Adder(LweSample* top1, const LweSample* a6, const LweSample* b6, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk){
//     LweSample* tmps6 = new_gate_bootstrapping_ciphertext_array(2, bk->params);
//     bootsCONSTANT(&tmps6[0], 0, bk); //initialize carry to 0

//     //run the elementary comparator gate n times//
        
//     for (int i=0; i<nb_bits; i++){
//         Addition(&top1[i], &a6[i], &b6[i], &tmps6[0], &tmps6[1], bk);
//     }
//     delete_gate_bootstrapping_ciphertext_array(2, tmps6);    
// }

void bootsADD1bit(LweSample* result, LweSample* a, LweSample* b, LweSample* carry, const TFheGateBootstrappingCloudKeySet* cloud_key){
    LweSample* tmp = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);
    LweSample* tmp_carry = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);
    LweSample* init_carry = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);
    bootsCOPY(&init_carry[0], carry, cloud_key);

    // Addition of the bits a, b and carry
    bootsXOR(&tmp[0], a, b, cloud_key);
    bootsXOR(result, &tmp[0], carry, cloud_key);

    // Update of the next carry
    bootsAND(&tmp[0], a, b, cloud_key);
    bootsCOPY(&tmp_carry[0], &tmp[0], cloud_key);
    bootsAND(&tmp[0], a, &init_carry[0], cloud_key);
    bootsXOR(carry, &tmp_carry[0], &tmp[0], cloud_key);
    bootsAND(&tmp[0], &init_carry[0], b, cloud_key);
    bootsXOR(&tmp_carry[0], carry, &tmp[0], cloud_key);
    bootsCOPY(carry, &tmp_carry[0], cloud_key);

    // Free
    delete_gate_bootstrapping_ciphertext_array(1, tmp);
    delete_gate_bootstrapping_ciphertext_array(1, tmp_carry);
    delete_gate_bootstrapping_ciphertext_array(1, init_carry);
}

void bootsADDNbit(LweSample* result, LweSample* a, LweSample* b, LweSample* carry, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key){

    LweSample* tmp_carry = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);
    //initialize the tmp_carry to 0
    bootsCONSTANT(&tmp_carry[0], 0, cloud_key);

    for (int i = 0; i < bitsize; ++i) {
        bootsADD1bit(&result[i], &a[i], &b[i], &tmp_carry[0], cloud_key);
    }
    bootsCOPY(&carry[0], &tmp_carry[0], cloud_key);

    // Free
    delete_gate_bootstrapping_ciphertext_array(1, tmp_carry);
}
void multiplexer(LweSample* rdbdata,LweSample* a,LweSample* b,LweSample* select_line,const int nb_bit, const TFheGateBootstrappingCloudKeySet* bk){
    int m=0;
    for(int i=0;i<nb_bit;i++){
        bootsMUX(&rdbdata[i],&select_line[m],&b[i],&a[i],bk);
    }
}

void multiply(LweSample* product, LweSample* a, LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk){
        
    LweSample* enc_theta=new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    for(int i=0;i<nb_bits;i++){ //initialize theta to all zero bits
        bootsCONSTANT(&enc_theta[i],0,bk);
    }
    for(int i=0;i<2*nb_bits;i++){ //initialize product to all zero bits
        bootsCONSTANT(&product[i],0,bk);
    } 

    for (int i=0; i<nb_bits; i++) {
        LweSample* temp_result=new_gate_bootstrapping_ciphertext_array(2 * nb_bits, bk->params);
        LweSample* partial_sum=new_gate_bootstrapping_ciphertext_array(2 * nb_bits, bk->params);
        for(int j=0;j<2*nb_bits;j++){ //initialize temp_result to all zero bits
            bootsCONSTANT(&temp_result[j],0,bk);
            bootsCONSTANT(&partial_sum[j],0,bk);
        } 
        LweSample* temp2=new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
        multiplexer(temp2,enc_theta,a,&b[i],nb_bits,bk);
        for(int j=0;j<nb_bits;j++){ 
            bootsCOPY(&temp_result[i+j],&temp2[j],bk);
        }

        //Add the valid result to partial_sum//
        Adder(partial_sum,product,temp_result,2*nb_bits,bk);
        //Change the partial sum to final product//
        for(int j=0;j<2*nb_bits;j++){ 
            bootsCOPY(&product[j],&partial_sum[j],bk);
        }
    }
}


void save_maping_graph(std::vector<int> g_maping_graph, char *path, int length)
{
	std::ofstream fp(path, std::ios::trunc);//只写文件 + trunc若文件存在则删除后重建
	//std::fstream fp(path, std::ios::out | std::ios::trunc);//只写文件 + trunc若文件存在则删除后新建
 
	if (!fp.is_open())
	{
		printf("can't open file\n");
		return;
	}
	for (int i = 0; i < length; i++)
	{
		fp << g_maping_graph[i];
		fp << " ";
	}
	fp.close();
}

int main(){  
    FILE* secret_key = fopen("client_folder/secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
    //reads the cloud key from file
    FILE* cloud_key = fopen("client_folder/cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = bk->params;
    // std::string cmd = "ls -l ./EM/ | grep \"^-\" | wc -l";
    // std::string fileNum;
    // exec_cmd(cmd, fileNum);
    // std::cout << atoi(fileNum.c_str()) << std::endl;
    // int fileNUM = atoi(fileNum.c_str());
    int fileNUM = 64;
    std::vector<LweSample*> cipherArray;
    FILE* cloud_data = fopen("client_folder/cloud_data","rb");
    for(int i =0; i < fileNUM; i++){
      LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(8, params);
        for (int j=0; j<8; j++) 
          import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext[j], params);
        // import_gate_bootstrapping_ciphertext_fromFile(cloud_data, ciphertext, params);
        cipherArray.push_back(ciphertext);
    }
    fclose(cloud_data);
    for(int i =0; i< fileNUM; i++){
          int8_t int_quotient = 0;
      for (int j=0; j<8; j++) {
          int ai = bootsSymDecrypt(&cipherArray[i][j], key)>0;
          int_quotient |= (ai<<j);
      }
      printf("%d ",int_quotient);
    }
    std::cout<<std::endl;
    int mulNum = fileNUM / 8;
    std::vector<int> ifmulList = GenerateRanNumber(0, fileNUM, mulNum);
    std::vector<int> ifMul(fileNUM);
    for(int i = 0;i < mulNum; i++){
      ifMul[ifmulList[i]] = 1;
    }
    for(int i = 0;i < fileNUM; i++){
      if(ifMul[i] != 1)
        ifMul[i]=0;
      printf("%d ",ifMul[i]);
    }
    std::vector<int> tempRandMulList = GenerateRanNumber(0, 127,mulNum);
    std::vector<int> randMulList(fileNUM);
    for(int i = 0, j = 0;i < fileNUM; i++){
      if(ifMul[i] == 1 )
        randMulList[i] = tempRandMulList[j++];
      else
        randMulList[i] = 1;
    }
    std::vector<LweSample*> tempMul;
    std::vector<LweSample*> tempAdd;
    LweSample* constant = new_gate_bootstrapping_ciphertext_array(16, params);
    for(int i =0; i < fileNUM; i++){
        for(int j =0; j < 16; j++)
          bootsCONSTANT(&constant[j], (randMulList[i]>>j)&1, bk);
        LweSample* temp = new_gate_bootstrapping_ciphertext_array(16, params);
        printf("%d ",randMulList[i]);
        if(ifMul[i] == 1){
          multiply(temp, cipherArray[i], constant, 8, bk);
        }
        else{
            for(int j=0; j < 8; j++)
              bootsCOPY(&temp[j],&cipherArray[i][j], bk);
            for(int j=8; j < 16; j++)
              bootsCONSTANT(&temp[j], 0, bk);
        }
        tempMul.push_back(temp);
    }
    std::cout<< "pause"<<std::endl;

    std::vector<int> randAddList = GenerateRanNumber(0, 127,fileNUM);
    for(int i =0; i < fileNUM; i++){
      for(int j =0; j < 16; j++)
        bootsCONSTANT(&constant[j], (randAddList[i]>>j)&1, bk);
      LweSample* temp= new_gate_bootstrapping_ciphertext_array(16, params);
      printf("%d ",randAddList[i]);
      Adder(temp, tempMul[i], constant, 16, bk);
      tempAdd.push_back(temp);
    }
    std::cout<< "pause"<<std::endl;
    FILE* confused_data = fopen("server_folder/confused_data","wb");
    for(int i = 0;i < tempAdd.size(); i++){
        for (int j=0; j<16; j++) 
            export_gate_bootstrapping_ciphertext_toFile(confused_data, &tempAdd[i][j], params);
    }
    fclose(confused_data);

	save_maping_graph(randAddList, "server_folder/client_X_randAddList", fileNUM);
	save_maping_graph(randMulList, "server_folder/client_X_randMulList", fileNUM);

    LweSample* remainder = new_gate_bootstrapping_ciphertext_array(16, params);
    //export the 32 ciphertexts to a file (for the cloud)
    FILE* answer_data = fopen("server_folder/confused_data","rb");
    for(int j = 0;j < fileNUM;j++){
        for (int i=0; i<16; i++) 
          import_gate_bootstrapping_ciphertext_fromFile(answer_data, &remainder[i], params);
        int answer = 0;
        for (int i=0; i<16; i++) {
          int ai = bootsSymDecrypt(&remainder[i], key)>0;
          answer |= (ai<<i);
        }
        std::cout<<answer<<" ";
    }
    fclose(answer_data);
    return 0;  
 }  