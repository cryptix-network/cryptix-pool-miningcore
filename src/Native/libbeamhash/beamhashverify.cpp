#include "beamhashverify.h"
#include <stdint.h>
#include "crypto/beamHashIII.h"
#include "crypto/equihashR.h"
#include "beam/core/difficulty.h"
#include "beam/core/uintBig.h"

#include <sodium.h>

#include <vector>

bool verifyBH(const char *hdr, const char *nonceBuffer, const std::vector<unsigned char> &soln, int pow){

  eh_HashState state;
  
  switch (pow) {
  	case 0:   BeamHashI.InitialiseState(state);
  		  break;
  	case 1:   BeamHashII.InitialiseState(state);
  		  break;
  	case 2:   BeamHashIII.InitialiseState(state);
  		  break;
  	default: 
  		throw std::invalid_argument("Unsupported PoW Parameter");
  }
  

  blake2b_update(&state, (const unsigned char *)hdr, 32);
  blake2b_update(&state, (const unsigned char *)nonceBuffer, 8);
  
  bool isValid;
  switch (pow) {
  	case 0:   isValid = BeamHashI.IsValidSolution(state, soln);
  		  break;
  	case 1:   isValid = BeamHashII.IsValidSolution(state, soln);
  		  break;
  	case 2:   isValid = BeamHashIII.IsValidSolution(state, soln);
  		  break;
  	default: 
  		throw std::invalid_argument("Unsupported PoW Parameter");
  }

  return isValid;
}