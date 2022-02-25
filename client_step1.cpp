#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <sstream>
#include <cstring>
#include <string>

#define MAX_MSG_SIZE 256*256
#define SERVER_PORT  9987
#define SERVER_IP "127.0.0.1"
 
void keygen(){
    //generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    //export the secret key to file for later use
    FILE* secret_key = fopen("client_folder/secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("client_folder/cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);
}
 
int GetServerAddr(char * addrname){  
    printf("please input server addr:");  
    scanf("%s",addrname);  
    return 1;  
}  
 
 
int main(){  

    // char buf[64] = {0x1,0x2,0x3,0x4,0x5,0x6, 0x7,0x8, 
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8, 
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
    // 0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8};
    char buf[64] = {0x61,0x61,0x61,0x61,0x61,0x61, 0x61,0x61, 
    0x61,0x61,0x61,0x61,0x61,0x61, 0x61,0x61, 
    0x61,0x61,0x61,0x61,0x61,0x61, 0x61,0x61, 
    0x61,0x61,0x61,0x61,0x61,0x61, 0x61,0x61, 
    0x61,0x61,0x61,0x61,0x61,0x61, 0x61,0x61, 
    0x61,0x61,0x61,0x61,0x61,0x61, 0x61,0x61, 
    0x61,0x61,0x61,0x61,0x61,0x61, 0x61,0x61, 
    0x61,0x61,0x61,0x61,0x61,0x61, 0x61,0x61 };
    keygen();

    FILE* secret_key = fopen("client_folder/secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

    LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(8, params);
    FILE* cloud_data = fopen("client_folder/cloud_data","wb");
    for(int i = 0;i < sizeof(buf); i++){
        for (int j=0; j<8; j++) {
            bootsSymEncrypt(&ciphertext[j], (buf[i]>>j)&1, key);
        }
        // export_gate_bootstrapping_ciphertext_toFile(cloud_data, ciphertext, params);
        for (int j=0; j<8; j++) 
            export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[j], params);
    }
    fclose(cloud_data);
    printf("Finished\n");/*在屏幕上打印出来 */  
    return 0;  
}  