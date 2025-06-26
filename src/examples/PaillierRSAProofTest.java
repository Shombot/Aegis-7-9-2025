package examples;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;

import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.PaillierProofOfEqualityDifferentGenerators;
import zero_knowledge_proofs.PaillierProofOfZero;
import zero_knowledge_proofs.PaillierRSAEqualityProofHelper;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;


public class PaillierRSAProofTest {
	public static void main(String args[]) {
		BigInteger lambda;
		BigInteger mu = null;

		BigInteger n;
		BigInteger n2;
		BigInteger g1;
		BigInteger g2;

		int bits = 2048;
		SecureRandom rand = new SecureRandom();
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(bits, rand);
			KeyPair keys = keyGen.genKeyPair();
			RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keys.getPrivate();

			BigInteger pm1 = privKey.getPrimeP().subtract(BigInteger.ONE);
			BigInteger qm1 = privKey.getPrimeQ().subtract(BigInteger.ONE);
			System.out.println(pm1.divide(BigInteger.TWO).isProbablePrime(50));
			System.out.println(qm1.divide(BigInteger.TWO).isProbablePrime(50));
			n = privKey.getModulus();
			n2 = n.pow(2);
			BigInteger mul = pm1.multiply(qm1);
			BigInteger gcd = pm1.gcd(qm1);
			BigInteger order = pm1.multiply(qm1);
			System.out.println(n.divideAndRemainder(order)[1]);
			//		        Util.destroyBigInteger(pm1);
			//		        Util.destroyBigInteger(qm1);
			pm1 = null;
			qm1 = null;
			//		        Util.destroyBigInteger(privKey.getPrimeP());
			lambda = mul.divide(gcd);

			g1 = n.add(BigInteger.ONE);
			g2 = g1.modPow(BigInteger.valueOf(54324), n2);
			try {
				mu = lFunction(g1.modPow(lambda, n2), n).modInverse(n);
			}catch(Exception e) {
			}
			while(mu == null) {
				g1 = new BigInteger(n.bitLength(), rand);
				try {
					BigInteger temp = g1.modPow(lambda, n2);
					BigInteger temp2 = lFunction(temp, n);

					mu = lFunction(temp2.modInverse(n), n);

				}catch(Exception e) {
					System.out.println("Error");
				}
			}	
			for(int i = 3; i <= 65537; i++) {
				BigInteger m = ZKToolkit.random(n, rand);
				BigInteger r = ZKToolkit.random(n, rand);
				BigInteger r2 = ZKToolkit.random(n, rand);
				BigInteger e = BigInteger.valueOf(i);

				BigInteger pailCipher = g1.modPow(m, n2).multiply(r.modPow(n, n2)).mod(n2);
							BigInteger pailCipher2 = g2.modPow(m, n2).multiply(r2.modPow(n, n2)).mod(n2);
							BigInteger pailCipher3 = r2.modPow(n, n2);
				BigInteger rsaCipher = m.modPow(e, n);

//			{// test equal messages different DL
//				CryptoData publicInputs = new CryptoDataArray(new BigInteger[] {pailCipher, pailCipher2});
//				CryptoData secrets = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(n, rand),ZKToolkit.random(n, rand),ZKToolkit.random(n, rand),r, r2, m});
//				CryptoData environment = new CryptoDataArray(new BigInteger[] {n, n2, g1, g2});
//				ZKPProtocol blah = new PaillierProofOfEqualityDifferentGenerators();
//				CryptoData[] blahOut = blah.proveFiatShamir(publicInputs, secrets, environment);
//				if(blah.verifyFiatShamir(publicInputs, blahOut[0], blahOut[1], environment)) {
//					System.out.println("preSuccess1");
//				} else {
//					System.out.println("preFail1");
//				}
//			}			
			{// test paillierHidesZero
				CryptoData publicInputs = new CryptoDataArray(new BigInteger[] {pailCipher3});
				CryptoData secrets = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(n, rand), r2});
				CryptoData environment = new CryptoDataArray(new BigInteger[] {n, n2, g2});
				ZKPProtocol blah = new PaillierProofOfZero();
				CryptoData[] blahOut = blah.proveFiatShamir(publicInputs, secrets, environment);
				if(blah.verifyFiatShamir(publicInputs, blahOut[0], blahOut[1], environment)) {
					System.out.println("preSuccess2");
				} else {
					System.out.println("preFail2");
				}
			}
				{
					CryptoData publicInputs = new CryptoDataArray(new BigInteger[] {rsaCipher, pailCipher});
					CryptoData secrets = new CryptoDataArray(new BigInteger[] {m, r});
					CryptoData environment = new CryptoDataArray(new BigInteger[] {n, n2, e, g1});

					CryptoData[] proverStuff = PaillierRSAEqualityProofHelper.proverGetIntermediateInputs(publicInputs, secrets, environment, rand);

					CryptoData[] verifierStuff = PaillierRSAEqualityProofHelper.verifierGetIntermediateInputs(publicInputs, proverStuff[0], environment);

					ZKPProtocol proof = PaillierRSAEqualityProofHelper.createProof(e);

					CryptoData[] fiatOutputs = proof.proveFiatShamir(proverStuff[1], proverStuff[2], proverStuff[3]);

					if(proof.verifyFiatShamir(verifierStuff[0], fiatOutputs[0], fiatOutputs[1], verifierStuff[1])) {
						System.out.println("Success! " + i);
					} else {
						System.out.println("Fail " + i);
					}
				}
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();

		} catch (ClassNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (MultipleTrueProofException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoTrueProofException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (ArraySizesDoNotMatchException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}


	}
	private static BigInteger lFunction(BigInteger x, BigInteger n) {
		BigInteger temp = (x.subtract(BigInteger.ONE)).divide(n);
		return temp;
	}
}
