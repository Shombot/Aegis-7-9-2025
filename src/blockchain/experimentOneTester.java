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
		
		
		//generate a random block for hashptrprevdata and hash it, rather than making it random
		//add timestamp onto the block header
		//hash the main block (in the blockNode)
		//fix the ZKP OR and AND to make sure they work together
		//make the condition codes a single 256 bit number
		//update the timer to make sure it doesnt count the time to generate patients and hospitals
		//DID I INCLUE THE HASH OF THE data off chain on the main block body/header?????
		//need to creaye a symmetric key encryption and decryption function
		for(int i = 0; i < numPatients; i++) {
			BlockChain.patients.add(BlockChain.generatePatient());
		}
		
		for(int i = 0; i < numHospitals; i++) {
			BlockChain.hospitals.add(BlockChain.generateHospital());
		}
		
		BlockChain bc = new BlockChain(numBlocks); //change nanme of testing zkp
		//this time also includes the time to generate the hospitals and patients as well, remember to subtract this out
		//chanmge blockchain ledger away from linked list (linked list has pointer to next, we need pointer to prev and not next)
		
	}
}