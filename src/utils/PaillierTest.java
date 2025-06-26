package utils;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.PaillierProofOfEqualityDifferentGenerators;
import zero_knowledge_proofs.PaillierProofOfKnowledge;
import zero_knowledge_proofs.PaillierProofOfZero;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class PaillierTest {
	public static void main(String[] args) {
		BigInteger p = BigInteger.valueOf(23);
		BigInteger q = BigInteger.valueOf(29);
		BigInteger n = p.multiply(q);
		BigInteger n2 = n.multiply(n);


		System.out.println(n);
		BigInteger lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		BigInteger mu = lambda.modInverse(n);
		
		BigInteger message = BigInteger.valueOf(314);
		SecureRandom rand = new SecureRandom("uygfiuhgdsaljgdsaofiugfjdsvgdiulsagfhdiuvhjzdkjvhbckxjzn".getBytes());
		BigInteger r = ZKToolkit.random(n, rand);
		BigInteger r2 = ZKToolkit.random(n, rand);
		BigInteger g = n.add(BigInteger.ONE);
		BigInteger cipher1 = g.modPow(message, n2).multiply(r.modPow(n,  n2)).mod(n2);
		BigInteger cipher2 = r.modPow(n,  n2);
		BigInteger cipher3 = cipher1.modPow(message, n2).multiply(r2.modPow(n,  n2)).mod(n2);
		BigInteger e = BigInteger.valueOf(3);
		
		
		ZKPProtocol blah = new PaillierProofOfKnowledge();
		ZKPProtocol blah2 = new PaillierProofOfZero();
		ZKPProtocol blah3 = new PaillierProofOfEqualityDifferentGenerators();
		
		CryptoData environment = new CryptoDataArray(new BigInteger[] {n, n2, g});
		{
			BigInteger rp = ZKToolkit.random(n, rand);
			BigInteger mp = ZKToolkit.random(n, rand);
			CryptoData publicInput = new CryptoDataArray(new BigInteger[] {cipher1});
			CryptoData secrets = new CryptoDataArray(new BigInteger[] {rp, mp, r, message});
			BigInteger challenge = new BigInteger (n.bitLength()-1, rand);
			try {
				CryptoData a = blah.initialComm(publicInput, secrets, environment);
				CryptoData z = blah.calcResponse(publicInput, secrets, challenge, environment);
				System.out.println(blah.verifyResponse(publicInput, a, z, challenge, environment));
			} catch (MultipleTrueProofException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (NoTrueProofException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (ArraySizesDoNotMatchException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			}
		}
		//pok simulator
		{
			BigInteger z1 = ZKToolkit.random(n, rand);
			BigInteger z2 = ZKToolkit.random(n, rand);
			BigInteger c = ZKToolkit.random(n, rand);
			CryptoData publicInput = new CryptoDataArray(new BigInteger[] {cipher1});
			CryptoData secrets = new CryptoDataArray(new BigInteger[] {z1, z2});
			BigInteger challenge = new BigInteger (n.bitLength()-1, rand);
			try {
				CryptoData a = blah.initialCommSim(publicInput, secrets, c, environment);
				CryptoData z = blah.simulatorGetResponse(publicInput, secrets);
				
				System.out.println(blah.verifyResponse(publicInput, a, z, c, environment));
			} catch (MultipleTrueProofException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (NoTrueProofException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (ArraySizesDoNotMatchException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			}
		}
		
		{		//FOR PROOF OF PAILLIER HIDES 0
			BigInteger z1 = ZKToolkit.random(n, rand);
			BigInteger c = ZKToolkit.random(n, rand);
			BigInteger rp = ZKToolkit.random(n, rand);
			CryptoData publicInput = new CryptoDataArray(new BigInteger[] {cipher2});  	//The ciphertext from cipher.getEncryptionProofData(m)
			CryptoData secrets = new CryptoDataArray(new BigInteger[] {z1});			//rp is proof ephemeral key, r is cipher ephemeral key
			try {
				CryptoData a = blah2.initialCommSim(publicInput, secrets, c, environment);
				CryptoData z = blah2.simulatorGetResponse(publicInput, secrets);
				System.out.println(blah2.verifyResponse(publicInput, a, z, c, environment));
			} catch (MultipleTrueProofException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (NoTrueProofException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (ArraySizesDoNotMatchException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			}
		}
		
		{		//FOR SIMULATOR OF PAILLIER HIDES 0
			BigInteger rp = ZKToolkit.random(n, rand);
			CryptoData publicInput = new CryptoDataArray(new BigInteger[] {cipher2});  	//The ciphertext from cipher.getEncryptionProofData(m)
			CryptoData secrets = new CryptoDataArray(new BigInteger[] {rp, r});			//rp is proof ephemeral key, r is cipher ephemeral key
			BigInteger challenge = new BigInteger (n.bitLength()-1, rand);				//challenge
			try {
				CryptoData a = blah2.initialComm(publicInput, secrets, environment);
				CryptoData z = blah2.calcResponse(publicInput, secrets, challenge, environment);
				System.out.println(blah2.verifyResponse(publicInput, a, z, challenge, environment));
			} catch (MultipleTrueProofException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (NoTrueProofException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (ArraySizesDoNotMatchException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			}
		}
		{
			CryptoData environment2 = new CryptoDataArray(new BigInteger[] {n, n2, g, cipher1});
		
			BigInteger r1p = ZKToolkit.random(n, rand);
			BigInteger r2p = ZKToolkit.random(n, rand);
			BigInteger mp = ZKToolkit.random(n, rand);
			CryptoData publicInput = new CryptoDataArray(new BigInteger[] {cipher1, cipher3});
			CryptoData secrets = new CryptoDataArray(new BigInteger[] {r1p, r2p, mp, r, r2, message});
			BigInteger challenge = new BigInteger (n.bitLength()-1, rand);
			try {
				CryptoData a = blah3.initialComm(publicInput, secrets, environment2);
				CryptoData z = blah3.calcResponse(publicInput, secrets, challenge, environment2);
//				{
//					BigInteger a1 = g.modPow(mp, n2).multiply(r1p.modPow(n, n2)).mod(n2);
//					BigInteger a2 = cipher1.modPow(mp, n2).multiply(r2p.modPow(n, n2)).mod(n2);
//					
//					System.out.println(a1);
//					System.out.println(a2);
//					System.out.println(a);
//					BigInteger z1 = challenge.multiply(message).add(mp).mod(n2);
//					BigInteger z2 = r.modPow(challenge, n2).multiply(r1p).mod(n);
//					BigInteger z3 = r2.modPow(challenge, n2).multiply(r2p).mod(n);
//					System.out.println(z1);
//					System.out.println(z2);
//					System.out.println(z3);
//					System.out.println(z);
//					BigInteger side1 = g.modPow(z1, n2).multiply(z2.modPow(n, n2)).mod(n2);
//					BigInteger side2 = cipher1.modPow(challenge, n2).multiply(a1).mod(n2);
//					
//					System.out.printf("%s ?= %s\n", side1, side2);
//					side1 = cipher1.modPow(z1, n2).multiply(z3.modPow(n, n2)).mod(n2);
//					side2 = cipher3.modPow(challenge, n2).multiply(a2).mod(n2);
//					
//					System.out.printf("%s ?= %s\n", side1, side2);
//				}
//				
				System.out.println(blah3.verifyResponse(publicInput, a, z, challenge, environment2));
			} catch (MultipleTrueProofException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (NoTrueProofException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (ArraySizesDoNotMatchException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			}
		}
		BigInteger g1 = ZKToolkit.random(n, rand);  	//
		BigInteger x = ZKToolkit.random(lambda, rand); 
		BigInteger x2 = ZKToolkit.random(lambda, rand); //
		BigInteger g2 = g1.modPow(x, n); 
		BigInteger h = g1.modPow(x2, n);				//
		BigInteger h2 = h.modPow(x, n);
		BigInteger rsaCipher1 = g2.modPow(e, n);
		BigInteger paillierCipher1 = g.modPow(message, n2).multiply(h2.modPow(n,n2)).mod(n2);
		BigInteger negCipher = paillierCipher1.modInverse(n2);
		
		
		System.out.printf("p = %s, q = %s, n = %s, n2 = %s, lambda = %s, mu = %s, message = %s, r = %s, cipher1 = %s\n", p, q, n, n2, lambda, mu, message, r, cipher1);
	}
}
