package blockchain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.UUID;

import examples.Working_AADProverBasicECSchnorrORExample;
import examples.Working_AADVerifierBasicECSchnorrORExample;

public class BlockChain {
	public static PublicKey groupKey = groupKeyGen();
	private static PrivateKey groupPrivateKey;
	public static final HashSet<Patient> patients = new HashSet<>();
	public static final HashSet<Hospital> hospitals = new HashSet<>();
	public static LinkedList<BlockNode> ledger = new LinkedList<>();
	public static final int numConditions = 100; //number of conditions possible (number of unique codes)
	public static final int maxConditions = 10; //max number of conditions a given patient can have
	
	public BlockChain(int n) {
		for(int i = 0; i < n; i++) {
			generateBlockNode();
		}
	}
	
	public static PublicKey groupKeyGen() {
        KeyPairGenerator keyGen = null;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
		} catch (Exception e) {
			e.printStackTrace();
		}

        SecureRandom secureRandom = new SecureRandom();
        keyGen.initialize(2048, secureRandom); // 2048-bit RSA key

        KeyPair keyPair = keyGen.generateKeyPair();

        groupPrivateKey = keyPair.getPrivate();
        groupKey = keyPair.getPublic();
        
        return groupKey;
	}
	
	public static Patient generatePatient() {
		String data = UUID.randomUUID().toString();
		String dataPtr = UUID.randomUUID().toString();
		String prevDataHashPtr = UUID.randomUUID().toString();
		
		while(true) {
			try {
				Patient p = new Patient(data, dataPtr, prevDataHashPtr);
				return p;
			} catch (NoSuchAlgorithmException e) {
				continue;
			}
		}
	}
	
	public static Hospital generateHospital() {
		String data = UUID.randomUUID().toString();
		String dataPtr = UUID.randomUUID().toString();
		String prevDataHashPtr = UUID.randomUUID().toString();
		
		while(true) {
			try {
				Hospital h = new Hospital(data, dataPtr, prevDataHashPtr);
				return h;
			} catch (NoSuchAlgorithmException e) {
				continue;
			}
		}
	}
	
	public BlockNode generateBlockNode() {
		String data;
		String dataPtr;
		String prevDataHashPtr;
		BlockNode blockNode;
		int numConditionsPatient;
		int[] conditions;
		
		while(true) {
			data = UUID.randomUUID().toString();
			dataPtr = UUID.randomUUID().toString();
			prevDataHashPtr = UUID.randomUUID().toString(); //not actually hashing previous block, this will be a random value for this testing
			numConditionsPatient = (int) (Math.random() * maxConditions);
			conditions = new int[numConditionsPatient];
			
			for(int i = 0; i < numConditionsPatient; i++) {
				conditions[i] = (int) (Math.random() * numConditions); //fill with random conditions
			}

			try {
				blockNode = new BlockNode(conditions, data, dataPtr, prevDataHashPtr);
				if(ledger.add(blockNode)) {
					break;
				}
			} catch(Exception e) {
				System.out.println("cant add blocknode " + e);
				continue;
			}
		}
		patients.add(blockNode.getPatient());
		hospitals.add(blockNode.getHospital());
		return blockNode;
	}
}
