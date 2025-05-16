package zero_knowledge_proofs;

import java.math.BigInteger;
import java.security.SecureRandom;

import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

/**
 * This is an abstract class designed to facilitate a proof of Paillier-RSA Equality.  This proof can be done by any party who knows the public key.
 */
public abstract class PaillierRSAEqualityProofHelper{
	
	
	/**
	 * This is a function designed to create the intermediate and proof CryptoData for a Proof of Paillier-RSA Equality
	 * 
	 * @param publicInput Public inputs structured as follows:  [RSA Cipher, Paillier Ciphertext]
	 * @param secrets Secret inputs only known to the Prover ordered as follows:  [m, r]
	 * @param environment Environment contains the constant public data associated with the given RSA and Paillier keys, ordered as follows:  [n, n2, e, g]
	 * @param rand:  A random number generator
	 * @return A CryptoData array of size 4 arranged as follows:  [intermediateC, proof public CryptoData, proof secret CryptoData, proof environment CryptoData]
	 */
	public static CryptoData[] proverGetIntermediateInputs(CryptoData publicInput, CryptoData secrets, CryptoData environment, SecureRandom rand){
		CryptoData[] pubArray = publicInput.getCryptoDataArray();
		CryptoData[] secArray = secrets.getCryptoDataArray();
		CryptoData[] envArray = environment.getCryptoDataArray();
		
		BigInteger rsaCipher = pubArray[0].getBigInt();
		BigInteger pailCipher = pubArray[1].getBigInt();
		
		BigInteger m = secArray[0].getBigInt();
		BigInteger r = secArray[1].getBigInt();
		
		BigInteger n = envArray[0].getBigInt();
		BigInteger n2 = envArray[1].getBigInt();
		BigInteger e = envArray[2].getBigInt();
		BigInteger g = envArray[3].getBigInt();
		
		int eLength = e.bitLength();
		CryptoData[] intermediateC = new CryptoData[eLength-1];
		
		CryptoData[] proof1Pub = new CryptoData[e.bitLength()-1];
		CryptoData[] proof2Pub = new CryptoData[e.bitCount()-1];
		
		CryptoData[] proof1Sec = new CryptoData[e.bitLength()-1];
		CryptoData[] proof2Sec = new CryptoData[e.bitCount()-1];
		
		CryptoData[] proof1Env = new CryptoData[e.bitLength()-1];
		CryptoData[] proof2Env = new CryptoData[e.bitCount()-1];
		
		BigInteger cIMinus1 = pailCipher;
		BigInteger muIMinus1 = m;
		BigInteger rhoIMinus1 = r;
		
		
		for(int i = 0, j = 0; i < e.bitLength()-1; i++) {
			
			BigInteger rhoI;
			BigInteger gamma = ZKToolkit.random(n, rand);
			BigInteger cPrimeI = cIMinus1.modPow(muIMinus1, n2).multiply(gamma.modPow(n, n2)).mod(n2);
			BigInteger muI;
			
			BigInteger cI = null;

			if(e.testBit((e.bitLength()-1)-(i+1))) { //if the bit is equal to 1

				BigInteger betaI = ZKToolkit.random(n, rand);
				cI = cPrimeI.modPow(m, n2).multiply(betaI.modPow(n, n2)).mod((n2));
				muI = muIMinus1.modPow(BigInteger.TWO, n).multiply(m).mod(n);
				rhoI = ((rhoIMinus1.modPow(muIMinus1, n).multiply(gamma)).modPow(m, n).multiply(betaI)).mod(n);
				//(rho^mu*gamma)^m*beta

//				System.out.printf("%d,    %s\n", i, cI);
				proof1Pub[i] = new CryptoDataArray(new CryptoData[] {new BigIntData(cIMinus1), new BigIntData(cPrimeI)});
				proof2Pub[j] = new CryptoDataArray(new CryptoData[] {pubArray[1], new BigIntData(cI)});
				
				proof1Sec[i] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(n, rand), ZKToolkit.random(n, rand), ZKToolkit.random(n, rand), rhoIMinus1, gamma, muIMinus1});
				proof2Sec[j] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(n, rand), ZKToolkit.random(n, rand), ZKToolkit.random(n, rand), r, betaI, m});

				proof1Env[i] = new CryptoDataArray(new CryptoData[] {envArray[0], envArray[1], envArray[3], new BigIntData(cIMinus1)});
				proof2Env[j] = new CryptoDataArray(new CryptoData[] {envArray[0], envArray[1], envArray[3], new BigIntData(cPrimeI)});
				
				intermediateC[i] = new CryptoDataArray(new CryptoData[] {new BigIntData(cPrimeI), new BigIntData(cI)});
				
				cIMinus1 = cI;
				
				j++;
			} else {
				muI = muIMinus1.modPow(BigInteger.TWO, n);
				rhoI = rhoIMinus1.modPow(muIMinus1, n).multiply(gamma).mod(n);

				proof1Pub[i] = new CryptoDataArray(new CryptoData[] {new BigIntData(cIMinus1), new BigIntData(cPrimeI)});
				proof1Sec[i] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(n, rand), ZKToolkit.random(n, rand), ZKToolkit.random(n, rand), rhoIMinus1, gamma, muIMinus1});
				proof1Env[i] = new CryptoDataArray(new CryptoData[] {envArray[0], envArray[1], envArray[3], new BigIntData(cIMinus1)});
				
				intermediateC[i] = new CryptoDataArray(new CryptoData[] {new BigIntData(cPrimeI)});
				
				cIMinus1 = cPrimeI;
			}
			muIMinus1 = muI;
			rhoIMinus1 = rhoI;
			
		}
//		if(cIMinus1.multiply(g.modPow(rsaCipher.negate(),n2)).mod(n2).equals(rhoIMinus1.modPow(n, n2))){
//			System.out.println("ghsdjkafhalsdfhask");
//			System.out.println(cIMinus1.mod(n2));
//		} else {
//
//			System.out.println("not ghsdjkafhalsdfhask");
//		}
		CryptoData proof3Pub = new CryptoDataArray(new CryptoData[] {new BigIntData(cIMinus1.multiply(g.modPow(rsaCipher.negate(), n2)).mod(n2))});
		CryptoData proof3Sec = new CryptoDataArray(new CryptoData[] {new BigIntData(ZKToolkit.random(n, rand)), new BigIntData(rhoIMinus1)});
		CryptoData proof3Env = new CryptoDataArray(new BigInteger[] {n, n2, g});
		
		CryptoData totalPub = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(proof1Pub), new CryptoDataArray(proof2Pub), proof3Pub});
		CryptoData totalSec = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(proof1Sec), new CryptoDataArray(proof2Sec), proof3Sec});
		CryptoData totalEnv = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(proof1Env), new CryptoDataArray(proof2Env), proof3Env});
		
		
		CryptoData[] toReturn = new CryptoData[4];
		toReturn[0] = new CryptoDataArray(intermediateC);
		toReturn[1] = totalPub;
		toReturn[2] = totalSec;
		toReturn[3] = totalEnv;
		
		return toReturn;
    }
	
	/**
	 * This function takes the public information, as well as the intermediate Paillier ciphertexts, and converts them into verifier CryptoData
	 * 
	 * @param publicInput Public inputs structured as follows:  [RSA Cipher, Paillier Ciphertext]
	 * @param intermediateC IntermediateC contains the intermediate ciphertexts required to prove the equality of the original Paillier ciphertext and the RSA ciphertext.
	 * @param environment Environment contains the constant public data associated with the given RSA and Paillier keys, ordered as follows:  [n, n2, e, g]
	 * @return The proof CryptoData required by the Verifier to verify the proof, structured as follows: [publicInputs, environment]
	 */
	public static CryptoData[] verifierGetIntermediateInputs(CryptoData publicInputs, CryptoData intermediateC, CryptoData environment) {
		CryptoData[] pubArray = publicInputs.getCryptoDataArray();
		CryptoData[] intermediateCArray = intermediateC.getCryptoDataArray();
		CryptoData[] envArray = environment.getCryptoDataArray();
	
		BigInteger rsaCipher = pubArray[0].getBigInt();
		BigInteger pailCipher = pubArray[1].getBigInt();
		
		BigInteger n = envArray[0].getBigInt();
		BigInteger n2 = envArray[1].getBigInt();
		BigInteger e = envArray[2].getBigInt();
		BigInteger g = envArray[3].getBigInt();
		
		CryptoData[] proof1Pub = new CryptoData[e.bitLength()-1];
		CryptoData[] proof2Pub = new CryptoData[e.bitCount()-1];
		
		CryptoData[] proof1Env = new CryptoData[e.bitLength()-1];
		CryptoData[] proof2Env = new CryptoData[e.bitCount()-1];
		
		
		BigInteger cIMinus1 = pailCipher;
		
		for(int i = 0, j = 0; i < e.bitLength()-1; i++) {
			CryptoData[] cInner = intermediateCArray[i].getCryptoDataArray();
			BigInteger cI;
			if(e.testBit((e.bitLength()-1)-(i+1))) { //if the bit is equal to 1
				BigInteger cPrimeI = cInner[0].getBigInt();
				cI = cInner[1].getBigInt();
				proof1Pub[i] = new CryptoDataArray(new BigInteger[] {cIMinus1, cPrimeI});
//				System.out.printf("%d,    %s\n", i, cI);
				proof2Pub[j] = new CryptoDataArray(new CryptoData[] {pubArray[1], new BigIntData(cI)});
				
				proof1Env[i] = new CryptoDataArray(new CryptoData[] {envArray[0], envArray[1], envArray[3], new BigIntData(cIMinus1)});
				proof2Env[j] = new CryptoDataArray(new CryptoData[] {envArray[0], envArray[1], envArray[3], new BigIntData(cPrimeI)});		

				j++;
			}
			else {
				cI = cInner[0].getBigInt();
				proof1Pub[i] = new CryptoDataArray(new BigInteger[] {cIMinus1, cI});

				proof1Env[i] = new CryptoDataArray(new CryptoData[] {envArray[0], envArray[1], envArray[3], new BigIntData(cIMinus1)});
			}
			cIMinus1 = cI;
		}
		
		CryptoData proof3Pub = new CryptoDataArray(new CryptoData[] {new BigIntData(cIMinus1.multiply(g.modPow(rsaCipher.negate(), n2)).mod(n2))});
		CryptoData proof3Env = new CryptoDataArray(new BigInteger[] {n, n2, g});
		
		CryptoData totalPub = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(proof1Pub), new CryptoDataArray(proof2Pub), proof3Pub});
		CryptoData totalEnv = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(proof1Env), new CryptoDataArray(proof2Env), proof3Env});
		
		
		CryptoData[] toReturn = new CryptoData[2];
		toReturn[0] = totalPub;
		toReturn[1] = totalEnv;
		
		return toReturn;
		
	}
	
	/**
	 * This function creates the compound Zero Knowledge Proof required to prove the equality of the messages in an RSA and Paillier ciphertext encrypted with encryption exponent e.
	 * 
	 * @param e An RSA encryption exponent
	 * @return The required Zero Knowledge Proof.
	 */
	public static ZKPProtocol createProof(BigInteger e) {
		ZKPProtocol proofOfEqualMessages = new PaillierProofOfEqualityDifferentGenerators();
		ZKPProtocol proofOfZero = new PaillierProofOfZero();
		
		
		ZKPProtocol[] proof1 = new ZKPProtocol[e.bitLength()-1];
		ZKPProtocol[] proof2 = new ZKPProtocol[e.bitCount()-1];
		int eLength = e.bitLength();
		int eCount = e.bitCount();
		for (int i = 0; i < eLength-1; i++) {
			proof1[i] = proofOfEqualMessages;
		}
		ZKPProtocol proof1Packed = new ZeroKnowledgeAndProver(proof1);
		
		for (int i = 0; i < eCount-1; i++) {
			proof2[i] = proofOfEqualMessages;
		}
		ZKPProtocol proof2Packed = new ZeroKnowledgeAndProver(proof2);
		
		ZKPProtocol toReturn = new ZeroKnowledgeAndProver(new ZKPProtocol[] {proof1Packed, proof2Packed, proofOfZero});
		return toReturn;
	}
	
	
}
