package examples;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Date;

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
		String delta = "1000000";
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

		System.out.println(new Date());
		long time1 = System.nanoTime();
		ConcealedTimeLockedPuzzle puzzle = new ConcealedTimeLockedPuzzle(n, p, q, BigInteger.valueOf(65537), m, h, new BigInteger(delta), rand);
		System.out.println(m);
		long time2 = System.nanoTime();
		System.out.println((time2-time1)/1000000000.0);
		puzzle.verifyPuzzle();
		long startWork = System.nanoTime();
		System.out.println((startWork-time2)/1000000000.0);
		System.out.println(puzzle.doWork(h));
		long end = System.nanoTime();
		System.out.println((end-startWork)/1000000000.0);
	}
}
