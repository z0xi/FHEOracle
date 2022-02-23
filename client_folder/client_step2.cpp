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
#include "client_step2.h"
#include "abycore/circuit/booleancircuits.h"
#include "abycore/sharing/sharing.h"
#include <ENCRYPTO_utils/cbitvector.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <cstring>

int32_t test_div_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing) {
	uint32_t bitlen_8 = 8;
	uint32_t bitlen_16 = 16;
	uint32_t zero = 0;
	uint32_t divbits_per_party = 8;
	uint32_t divbytes_per_party = bits_in_bytes(divbits_per_party);
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen_8, nthreads, mt_alg);
	std::vector<Sharing*>& sharings = party->GetSharings();

	// uint8_t* output;
	CBitVector out;
	Circuit* temp_circ = sharings[sharing]->GetCircuitBuildRoutine();
	BooleanCircuit* circ = (BooleanCircuit*) temp_circ;
	//Circuit build routine works for Boolean circuits only right now
	assert(circ->GetCircuitType() == C_BOOLEAN);
	uint32_t aa[6] = {10,10,10,10,10,10};
	uint32_t bb[6] = {1,1,1,1,1,1};
	uint32_t cc[6] = {101,201,301,401,501,601};
	std::vector<share*> msgV;
	for(int i = 0;i < 6;i++){
		share *s_div_out, *s_msg, *s_divRand, *s_subRand;
		s_msg = circ->PutINGate(cc[i], bitlen_16, CLIENT);
		s_subRand = circ->PutINGate(bb[i], bitlen_8, SERVER);
		s_divRand = circ->PutINGate(aa[i], bitlen_8, SERVER);

		share* s_quotient = inverseRandom(s_msg, s_divRand, s_subRand, nvals, circ);
		s_div_out = circ->PutOUTGate(s_quotient, ALL);
		msgV.push_back(s_div_out);
		circ->PutPrintValueGate(s_quotient , "s_quotient");
	}
	party->ExecCircuit();
	out.Create(6*8);
	for(int i = 0;i < 6;i++){
		uint8_t* output = msgV[i]->get_clear_value_ptr();
		// out.AttachBuf(output, (uint64_t) 8 * nvals);
		out.SetBytes(output, i, 1);
	}

	for (uint32_t i = 0; i < nvals; i++) {
// #ifndef BATCH
		// std::cout << "(" << i << ") Server Input:\t";
		// msgS.PrintHex(i * sha1bytes_per_party, (i + 1) * sha1bytes_per_party);
		// std::cout << "(" << i << ") Client Input:\t";
		// msgC.PrintHex(i * sha1bytes_per_party, (i + 1) * sha1bytes_per_party);
		std::cout << "(" << i << ") Circ:\t";
		out.PrintHex(i * 8, (i + 1) * 8);
// #endif
	}
	delete party;

	return 0;
}

share* inverseRandom(share* msg, share* divRand, share* subRand, uint32_t nvals, BooleanCircuit* circ){
	uint32_t zero = 0;
	uint32_t one = 0;
	share* s_zero= circ->PutCONSGate(zero, 16);
	share* s_one= circ->PutCONSGate(one, 16);
	share* s_temp = circ->PutCONSGate(zero, 16);

	for(uint32_t j = 0; j < 8; j++) {
		s_temp->set_wire_id(j, subRand->get_wire_id(j));
	}
	msg = circ->PutSUBGate(msg, s_temp);
	circ->PutPrintValueGate(msg , "msg");
	share* s_quotient = BuildDivCircuit(msg, divRand, nvals, circ);
	return s_quotient;
	// uint8_t *output_remainder;
	// share* s_out_remainder = circ->PutOUTGate(s_remainder, ALL);
	// output_remainder = s_out_remainder->get_clear_value_ptr();
	// std::cout<< "tset remainder"<<output_remainder[0]<<std::endl;
};


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
