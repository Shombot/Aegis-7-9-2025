package blockchain;

import java.security.NoSuchAlgorithmException;
import java.util.UUID;

public class experimentOneTester {
	public static void main(String[] args) {
		String data;
		String dataPtr;
		String prevDataHashPtr;
		int numHospitals = 10;
		int numPatients = 100;
		int numBlocks = 1; //number of blocks we are generating
		
		
		for(int i = 0; i < numPatients; i++) {
			data = UUID.randomUUID().toString();
			dataPtr = UUID.randomUUID().toString();
			prevDataHashPtr = UUID.randomUUID().toString(); //not actually hashing previous block, this will be a random value for this testing
			
			try {
				BlockChain.patients.add(new Patient(data, dataPtr, prevDataHashPtr));
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}
		
		for(int i = 0; i < numHospitals; i++) {
			data = UUID.randomUUID().toString();
			dataPtr = UUID.randomUUID().toString();
			prevDataHashPtr = UUID.randomUUID().toString(); //not actually hashing previous block, this will be a random value for this testing
			
			try {
				BlockChain.hospitals.add(new Hospital(data, dataPtr, prevDataHashPtr));
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}
		
		BlockChain bc = new BlockChain(numBlocks); //change nanme of testing zkp
		//this time also includes the time to generate the hospitals and patients as well, remember to subtract this out
		//chanmge blockchain ledger away from linked list (linked list has pointer to next, we need pointer to prev and not next)
		
	}
}
