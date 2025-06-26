package concealed_time_locked_puzzle;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;

import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.DLEqualDiscreteLogsRSAProver;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.PaillierRSAEqualityProofHelper;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.ZeroKnowledgeAndProver;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class ConcealedTimeLockedPuzzle implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 4521566575437549862L;
	//values private to creator
	private transient BigInteger rM;
	private transient BigInteger rH;
	private transient BigInteger p;
	private transient BigInteger q;
	private transient BigInteger m;
	private transient BigInteger h;

	//values public to solver
	private BigInteger c1;
	private BigInteger c2;
	private BigInteger c3;
	private BigInteger c4;
	private BigInteger c5;
	private BigInteger c6;
	private BigInteger n;
	private BigInteger e;
	private BigInteger delta;

	private CryptoData[] step3ProofDataAndTranscript;
	private CryptoData[] step4ProofDataAndTranscript;
	private CryptoData[] step5Transcript;
	private BigInteger[] step5Numbers;


	public ConcealedTimeLockedPuzzle(BigInteger m, BigInteger h, BigInteger delta, int bits, SecureRandom rand) {
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(bits, rand);
			KeyPair keys = keyGen.genKeyPair();
			RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keys.getPrivate();
			p = privKey.getPrimeP();
			q = privKey.getPrimeQ();
			n = privKey.getModulus();
			e = BigInteger.valueOf(65537);
			this.delta = delta;
			this.m = m;
			this.h = h;
			
			initialize(rand);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	public ConcealedTimeLockedPuzzle(BigInteger n, BigInteger p, BigInteger q, BigInteger e, BigInteger m, BigInteger h, BigInteger delta, SecureRandom rand) {
		this.n = n;
		this.p = p;
		this.q = q;
		this.e = e;
		this.m = m;
		this.h = h;
		this.delta = delta;
		initialize(rand);
	}
	private void initialize(SecureRandom rand) {
		if(m.compareTo(n) >= 0 || h.compareTo(n) >= 0) {
			throw new ArithmeticException("m and h must be less than n");
		}
		if(m.signum() != 1 || h.signum() != 1) {
			throw new ArithmeticException("m and h must be greater than 0");
		}
		//Pre-work
		BigInteger n2 = n.pow(2);
		BigInteger g = n.add(BigInteger.ONE);

		BigInteger pm1 = p.subtract(BigInteger.ONE);
		BigInteger qm1 = q.subtract(BigInteger.ONE);

		BigInteger orderN = pm1.multiply(qm1);

		BigInteger totalPuzzleExponent = BigInteger.TWO.modPow(delta, orderN);

		rM = ZKToolkit.random(n, rand);
		rH = ZKToolkit.random(n, rand);


		//Define terms
		c1 = m.modPow(e, n);
		c2 = h.modPow(e, n);
		c3 = c2.modPow(totalPuzzleExponent, n);
		c4 = g.modPow(m, n2).multiply(rM.modPow(n, n2)).mod(n2);
		c5 = g.modPow(h, n2).multiply(rH.modPow(n, n2)).mod(n2);
		c6 = m.multiply(h.modPow(totalPuzzleExponent, n)).mod(n);

		//Create proofs, blocks for variable name scoping
		try {
			CryptoData environment = new CryptoDataArray(new BigInteger[] {n, n2, e, g});
			ZKPProtocol proof = PaillierRSAEqualityProofHelper.createProof(e);
			{
				CryptoData publicInputs = new CryptoDataArray(new BigInteger[] {c1, c4});
				CryptoData secrets = new CryptoDataArray(new BigInteger[] {m, rM});
				CryptoData[] proofDataOut = PaillierRSAEqualityProofHelper.proverGetIntermediateInputs(publicInputs, secrets, environment, rand);
				CryptoData[] transcript = proof.proveFiatShamir(proofDataOut[1], proofDataOut[2], proofDataOut[3]);
				step3ProofDataAndTranscript = new CryptoData[] {transcript[0], transcript[1], proofDataOut[0]};
			}
			{

				CryptoData publicInputs = new CryptoDataArray(new BigInteger[] {c2, c5});
				CryptoData secrets = new CryptoDataArray(new BigInteger[] {h, rH});
				CryptoData[] proofDataOut = PaillierRSAEqualityProofHelper.proverGetIntermediateInputs(publicInputs, secrets, environment, rand);
				CryptoData[] transcript = proof.proveFiatShamir(proofDataOut[1], proofDataOut[2], proofDataOut[3]);
				step4ProofDataAndTranscript = new CryptoData[] {transcript[0], transcript[1], proofDataOut[0]};
			}
		} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
				| ArraySizesDoNotMatchException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		//This proof will use Diffie Hellman to prove the relationship between h^e and (h^e)^(2^delta) by square and multiply.
		{
			int deltaLength = delta.bitLength();
			step5Numbers = new BigInteger[delta.bitLength()];
			BigInteger currentExponent = BigInteger.ONE;
			step5Numbers[0] = c2;
			
			BigInteger aZ;  //a^z
			BigInteger aZ2; //a^(z^2)
			CryptoData[] pubInputsArray = new CryptoData[deltaLength-1]; 
			CryptoData[] secInputsArray = new CryptoData[deltaLength-1]; 
			CryptoData[] envInputsArray = new CryptoData[deltaLength-1]; 
			ZKPProtocol[] innerProof = new ZKPProtocol[deltaLength-1];
			ZKPProtocol basicProof = new DLEqualDiscreteLogsRSAProver();
			for(int i = 1; i < deltaLength; i++) {
				aZ = step5Numbers[i-1];
				if(delta.testBit((deltaLength-i))) {
					aZ = aZ.modPow(BigInteger.TWO, n);
					currentExponent = currentExponent.multiply(BigInteger.TWO).mod(orderN);
					
				}
				aZ2 = step5Numbers[i] = aZ.modPow(currentExponent, n);
				//Prove that a to aZ shares the same exponent as aZ to aZ2 using diffie hellman
				BigInteger[] innerPubInputs = new BigInteger[] {aZ, aZ2};
				BigInteger[] innerSecInputs = new BigInteger[] {ZKToolkit.random(orderN, rand), currentExponent, orderN};
				BigInteger[] innerEnvInputs = new BigInteger[] {n, c2, aZ};
				
				currentExponent = currentExponent.modPow(BigInteger.TWO, orderN);
				pubInputsArray[i-1] = new CryptoDataArray(innerPubInputs);
				secInputsArray[i-1] = new CryptoDataArray(innerSecInputs);
				envInputsArray[i-1] = new CryptoDataArray(innerEnvInputs);
				
				innerProof[i-1] = basicProof;
			}
			ZKPProtocol proof = new ZeroKnowledgeAndProver(innerProof);
			try {
				step5Transcript = proof.proveFiatShamir(new CryptoDataArray(pubInputsArray), new CryptoDataArray(secInputsArray), new CryptoDataArray(envInputsArray));
			} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
					| ArraySizesDoNotMatchException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}

	}
	
	public BigInteger getRM() {
		return rM;
	}
	public BigInteger getRH() {
		return rH;
	}
	public boolean verifyPuzzle() {
		BigInteger n2 = n.pow(2);
		BigInteger g = n.add(BigInteger.ONE);
		CryptoData env = new CryptoDataArray(new BigInteger[] {n, n2, e, g});
		//step 3
		{
			CryptoData publicInputs = new CryptoDataArray(new BigInteger[] {c1, c4});
			
			CryptoData[] pubProofData = PaillierRSAEqualityProofHelper.verifierGetIntermediateInputs(publicInputs, step3ProofDataAndTranscript[2], env);
			ZKPProtocol proof = PaillierRSAEqualityProofHelper.createProof(e);
			try {
				if(!proof.verifyFiatShamir(pubProofData[0], step3ProofDataAndTranscript[0], step3ProofDataAndTranscript[1], pubProofData[1])) {
					System.out.println("Failed Proof 3");
					return false;
				}
			} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
					| ArraySizesDoNotMatchException e1) {
				e1.printStackTrace();
				return false;
			}
		}
		//step 4{
		CryptoData publicInputs = new CryptoDataArray(new BigInteger[] {c2, c5});
		
		CryptoData[] pubProofData = PaillierRSAEqualityProofHelper.verifierGetIntermediateInputs(publicInputs, step4ProofDataAndTranscript[2], env);
		ZKPProtocol proof1 = PaillierRSAEqualityProofHelper.createProof(e);
		try {
			if(!proof1.verifyFiatShamir(pubProofData[0], step4ProofDataAndTranscript[0], step4ProofDataAndTranscript[1], pubProofData[1])) {
				System.out.println("Failed Proof 4");
				return false;
			}
		} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
				| ArraySizesDoNotMatchException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return false;
		}
		//step 5
		{
			int deltaLength = delta.bitLength();BigInteger aZ;  //a^z
			BigInteger aZ2; //a^(z^2)
			CryptoData[] pubInputsArray = new CryptoData[deltaLength-1]; 
			CryptoData[] envInputsArray = new CryptoData[deltaLength-1]; 
			ZKPProtocol[] innerProof = new ZKPProtocol[deltaLength-1];
			ZKPProtocol basicProof = new DLEqualDiscreteLogsRSAProver();
			for(int i = 1; i < deltaLength; i++) {
				aZ = step5Numbers[i-1];
				if(delta.testBit((deltaLength-i))) {
					aZ = aZ.modPow(BigInteger.TWO, n);
				}
				aZ2 = step5Numbers[i];
				//Prove that a to aZ shares the same exponent as aZ to aZ2 using diffie hellman
				BigInteger[] innerPubInputs = new BigInteger[] {aZ, aZ2};
				BigInteger[] innerEnvInputs = new BigInteger[] {n, c2, aZ};
				
				pubInputsArray[i-1] = new CryptoDataArray(innerPubInputs);
				envInputsArray[i-1] = new CryptoDataArray(innerEnvInputs);
				
				innerProof[i-1] = basicProof;
			}
			ZKPProtocol proof2 = new ZeroKnowledgeAndProver(innerProof);
			try {
				if(!proof2.verifyFiatShamir(new CryptoDataArray(pubInputsArray), step5Transcript[0], step5Transcript[1], new CryptoDataArray(envInputsArray))){
					System.out.println("Failed Step 5");
					return false;
				}
			} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
					| ArraySizesDoNotMatchException e1) {
				// TODO Auto-generated catch block
				System.out.println("Failed Step 5");
				return false;
			}
			BigInteger result = step5Numbers[step5Numbers.length-1];
			if(delta.testBit(0)) {
				result = result.modPow(BigInteger.TWO, n);
			}
			if (!result.equals(c3)) {
				System.out.println("Failed Step 5");
			}
		}
		//step 6
		if(!c1.multiply(c3).mod(n).equals(c6.modPow(e, n))) {
			System.out.println("Failed step 6.");
			return false;
		}
		
		return true;
	}
	public BigInteger doWork(BigInteger discoveredH) {
		BigInteger delta = this.delta;
		BigInteger inProgress = discoveredH;
		while(!delta.equals(BigInteger.ZERO)) {
			inProgress = inProgress.modPow(BigInteger.TWO, n); 
			delta = delta.subtract(BigInteger.ONE); 
		}
		return c6.multiply(inProgress.modInverse(n)).mod(n);
	}
	
	public BigInteger doWork(BigInteger discoveredH, File file) {
		BigInteger delta = this.delta;
		BigInteger inProgress = discoveredH;
		if(file.exists()) {
			try {
				ObjectInputStream in = new ObjectInputStream(new FileInputStream(file));
				delta = (BigInteger) in.readObject();
				inProgress = (BigInteger) in.readObject();
				in.close();
			} catch (Exception e) {
				try {
					File backup = new File(file.getPath() + ".bak");
					if(backup.exists()) {
						ObjectInputStream in = new ObjectInputStream(new FileInputStream(backup));
						delta = (BigInteger) in.readObject();
						inProgress = (BigInteger) in.readObject();
						in.close();
					}
				}
				catch(Exception e2) {
					delta = this.delta;
					inProgress = discoveredH;
				}
			}
		}
		final BigInteger saveFrequency = BigInteger.valueOf(500000);
		Thread saveProcess = null;
		while(!delta.equals(BigInteger.ZERO)) {
			inProgress = inProgress.modPow(BigInteger.TWO, n); 
			delta = delta.subtract(BigInteger.ONE); 
			if(file != null && delta.mod(saveFrequency).equals(BigInteger.ZERO)) {
				try {
					saveProcess.join();
					saveProcess = new Thread(new SaveThread(delta, inProgress, file));
					saveProcess.start();
				} catch (Exception e) {
					
				}
			}
		}
		if(file != null) {
			try {
				saveProcess.join();
				saveProcess = new Thread(new SaveThread(delta, inProgress, file));
				saveProcess.start();
				saveProcess.join();
			} catch (Exception e) {
				
			}
		}
		return c6.multiply(inProgress.modInverse(n)).mod(n);
	}
	public BigInteger getMCipher() {
		return c4;
	}
	public BigInteger getHCipher() {
		return c5;
	}
	private static class SaveThread implements Runnable {
		private BigInteger delta;
		private BigInteger inProgress;
		private File file;
		
		public SaveThread(BigInteger delta, BigInteger inProgress, File file) {
			this.delta = delta;
			this.inProgress = inProgress;
			this.file = file;
		}

		@Override
		public void run() {
			File backup = new File(file.getPath() + ".bak");
			ObjectOutputStream out;
			try {
				Files.copy(file.toPath(), backup.toPath(), StandardCopyOption.REPLACE_EXISTING);
				out = new ObjectOutputStream(new FileOutputStream(file, false));
				out.writeObject(delta);
				out.writeObject(inProgress);
				out.flush();
				out.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	public BigInteger getN() {
		return n;
	}

	public BigInteger getG() {
		return n.add(BigInteger.ONE);
	}
	public BigInteger getDelta() {
		return delta;
	}
}
