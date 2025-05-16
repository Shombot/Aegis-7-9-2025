package examples;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;

import concealed_time_locked_puzzle.ConcealedTimeLockedPuzzle;
import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.DLEqualDiscreteLogsRSAProver;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class ConcealedTimeLockedPuzzleTest {
	public static void main(String[] args) throws NoSuchAlgorithmException {
		int bits = 2048;
		SecureRandom rand = new SecureRandom();
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(bits, rand);
		KeyPair keys = keyGen.genKeyPair();
		RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keys.getPrivate();

		BigInteger pm1 = privKey.getPrimeP().subtract(BigInteger.ONE);
		BigInteger qm1 = privKey.getPrimeQ().subtract(BigInteger.ONE);
		BigInteger order = pm1.multiply(qm1);
		
		BigInteger n = privKey.getModulus();
		BigInteger p = privKey.getPrimeP();
		BigInteger q = privKey.getPrimeQ();
		
		BigInteger m = ZKToolkit.random(n, rand);
		BigInteger h = ZKToolkit.random(n, rand);

		{ //Test DLEqualDiscreteLogsRSAProver 
			BigInteger x = ZKToolkit.random(order, rand);
			BigInteger y1 = m.modPow(x, n);
			BigInteger y2 = h.modPow(x, n);
			CryptoData pubInputs = new CryptoDataArray(new BigInteger[] {y1, y2});
			CryptoData secInputs = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rand), x, order});
			CryptoData envInputs = new CryptoDataArray(new BigInteger[] {n, m, h});
			ZKPProtocol proof = new DLEqualDiscreteLogsRSAProver();
			try {
				CryptoData[] transcript = proof.proveFiatShamir(pubInputs, secInputs, envInputs);
				if(proof.verifyFiatShamir(pubInputs, transcript[0], transcript[1], envInputs)) {
					System.out.println("DL proof accepted");
				} else {
					System.out.println("DL proof failed!!!!!!!!!!!!!");
				}
			} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
					| ArraySizesDoNotMatchException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		ConcealedTimeLockedPuzzle puzzle = new ConcealedTimeLockedPuzzle(n, p, q, BigInteger.valueOf(65537), m, h, BigInteger.valueOf(1000000), rand);
		System.out.println(m);
		puzzle.verifyPuzzle();
		System.out.println(puzzle.doWork(h).mod(n));
	}
}
