/**
 \file 		sha1_circuit.cpp
 \author 	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Implementation of the SHA1 hash function (which should not be used in practice anymore!)
 */
#include "client_step2_circuit.h"
#include "abycore/circuit/booleancircuits.h"
#include "abycore/sharing/sharing.h"
#include <ENCRYPTO_utils/cbitvector.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <cstring>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

share* BuildDivCircuit(share* dividend, share* divisor, uint32_t nvals, BooleanCircuit* circ) {

	uint32_t zero = 0;
	uint32_t one = 1;
	share* s_zero = circ->PutCONSGate(zero, 16);
	share* s_one = circ->PutCONSGate(one, 16);
	share* s_quotient = circ->PutCONSGate( zero, 16);
	share* s_remainder = circ->PutCONSGate(zero, 16);
	for(uint32_t j = 0; j < 15; j++) {
		s_remainder->set_wire_id(j, dividend->get_wire_id(j));
	}
	share* s_divisor = circ->PutCONSGate(zero, 16);
	for(uint32_t j = 15; j > 7; j--) {
			s_divisor->set_wire_id(j, divisor->get_wire_id(j-8));
	}
	int cnt = 9;

	do
    {
		share* s_temp = circ->PutSUBGate(s_remainder, s_divisor);
		// circ->PutPrintValueGate(s_temp , "temp s_temp");
		share* s_flag = circ->PutMUXGate(s_one, s_zero, s_temp->get_wire_ids_as_share(15));
		s_remainder = circ->PutMUXGate(s_remainder, s_temp, s_flag);
		// circ->PutPrintValueGate(s_remainder , "temp after flag s_remainder");
		share* lastbit = circ->PutMUXGate(s_zero->get_wire_ids_as_share(0), s_one->get_wire_ids_as_share(0), s_flag->get_wire_ids_as_share(0));
    	// circ->PutPrintValueGate(lastbit , "temp lastbit");
		// circ->PutPrintValueGate(s_quotient , "temp 1 s_quotient");
		s_quotient = circ->PutLeftShifterGate(s_quotient, one);
		// circ->PutPrintValueGate(s_quotient , "temp 2 s_quotient");
		s_quotient->set_wire_id(0, lastbit->get_wire_id(0));
		// circ->PutPrintValueGate(s_quotient , "temp 3 s_quotient");
		s_divisor = circ->PutBarrelRightShifterGate(s_divisor, s_one);
		s_divisor->set_wire_id(15, s_zero->get_wire_id(0));
		// circ->PutPrintValueGate(s_quotient , "temp s_quotient");
		cnt --;
    }while(cnt!=0);
	circ->PutPrintValueGate(s_quotient , "final s_quotient");
	share* flag = circ->PutEQGate(s_remainder, s_zero);
	circ->PutPrintValueGate(flag , "flag");
	circ->PutAssertGate(flag, one, 16);
	return s_quotient;
}

share* BuildInverseRandomCircuit(share* msg, share* divRand, share* subRand, uint32_t fileNUM, uint32_t nvals, BooleanCircuit* circ){
	uint32_t zero = 0;
	uint32_t one = 0;
	uint32_t bitlen_8 = 8;
	share* out = new boolshare(bitlen_8 * fileNUM, circ);
	int subIndex = 0;
	int msgIndex = 0;
	int divIndex = 0;
	int outIndex = 0;
	for(int i =0; i < fileNUM; i++){
		share* s_zero= circ->PutCONSGate(zero, 16);
		share* s_one= circ->PutCONSGate(one, 16);
		share* s_sub_temp = circ->PutCONSGate(zero, 16);
		share* s_div_temp = circ->PutCONSGate(zero, 16);
		share* s_msg_temp = circ->PutCONSGate(zero, 16);
		for(uint32_t j = 0; j < 8; j++) {
			s_sub_temp->set_wire_id(j, subRand->get_wire_id(subIndex++));
			s_div_temp->set_wire_id(j, divRand->get_wire_id(divIndex++));
		}
		for(uint32_t j = 0; j < 16; j++) {
			s_msg_temp->set_wire_id(j, msg->get_wire_id(msgIndex++));
		}
		circ->PutPrintValueGate(s_msg_temp, "sub_before");
		s_msg_temp = circ->PutSUBGate(s_msg_temp, s_sub_temp);
		circ->PutPrintValueGate(s_msg_temp, "sub_after");
		share* s_quotient = BuildDivCircuit(s_msg_temp, s_div_temp, nvals, circ);
		for(uint32_t j = 0; j < 8; j++) {
			out->set_wire_id(outIndex++, s_quotient->get_wire_id(j));
		}
	}
	return out;
};



int32_t test_protocol_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing) {
	uint32_t bitlen_8 = 8;
	uint32_t bitlen_16 = 16;
	uint32_t fileNUM = 64;
	uint32_t divbits_per_party = 8;
	uint32_t divbytes_per_party = bits_in_bytes(divbits_per_party);
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen_16, nthreads, mt_alg);
	std::vector<Sharing*>& sharings = party->GetSharings();
	Circuit* temp_circ = sharings[sharing]->GetCircuitBuildRoutine();
	BooleanCircuit* circ = (BooleanCircuit*) temp_circ;

    FILE* secret_key = fopen("client_folder/secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
	const TFheGateBootstrappingParameterSet* params = key->params;
    fclose(secret_key);
	FILE* answer_data = fopen("server_folder/confused_data","rb");
	LweSample* confused_data = new_gate_bootstrapping_ciphertext_array(16, params);
	uint16_t msgArray[fileNUM];
	for(int j = 0;j < fileNUM;j++){
        for (int i=0; i<16; i++) 
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &confused_data[i], params);
        uint16_t answer = 0;
        for (int i=0; i<16; i++) {
          int ai = bootsSymDecrypt(&confused_data[i], key)>0;
          answer |= (ai<<i);
        }
		msgArray[j] = answer;
        printf("%d ",answer);
    }
	fclose(answer_data);

	// CBitVector msgShare;
	// msgShare.Create(bitlen_16*fileNUM);
	// for(uint32_t i = 0; i < fileNUM; i++) {
		// msgShare.SetByte(i, msgArray[i]);
	// }

	// circ->PutSIMDINGate(nvals, msgShare.GetArr(), bitlen_16*fileNUM, CLIENT);
	share *s_div_out, *s_msg, *s_divRand, *s_subRand;
	s_msg = circ->PutSIMDINGate(nvals, msgArray, bitlen_16*fileNUM, CLIENT);
	s_subRand = circ->PutDummyINGate(bitlen_8*fileNUM);
	s_divRand = circ->PutDummyINGate(bitlen_8*fileNUM);

	share* s_quotient = BuildInverseRandomCircuit(s_msg, s_divRand, s_subRand, fileNUM, nvals, circ);
	s_div_out = circ->PutOUTGate(s_quotient, SERVER);

	party->ExecCircuit();
	CBitVector out;
	out.AttachBuf(s_div_out->get_clear_value_ptr(), (uint64_t) bitlen_8*fileNUM * nvals);

	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "(" << i << ") Circ:\t";
		out.PrintHex(i * 8, (i + 1) * 8);
	}
	delete party;
	return 0;
}