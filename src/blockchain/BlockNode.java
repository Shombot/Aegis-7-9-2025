package blockchain;

import java.io.IOException;

import examples.AND_Fiat_Shamir_AABProverBasicDLSchnorrANDExample;
import examples.OR_Fiat_Shamir_AADProverBasicECSchnorrORExample;
import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class BlockNode {
	/*
	 * HEADER
	 * hash of this block (hash of everything besides this part) h
	 * pointer to previous block (to establish linked list structure) h
	 * ZKP patient signature h
	 * ZKP hospital signature h
	 * 
	 * BLOCK
	 * pointer to data, encrypted by symK b
	 * symK encrypted by groupK b
	 * HashPointer to the previous block for this patient, encrypted with the new public key b
	 * Patient new public key b
	 * Hospital new public key b
	 * hash of the unencrypted off chain data for this block b
	*/
	
	private BlockHeader header;
	private BlockBody body;
	private String hash;
	
	public BlockNode(int[] conditionCodes, String data, String ptrData, String hashPtrPrevBlock) throws ClassNotFoundException, IOException, MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException, InterruptedException {
		while(true) {
			try {
				body = new BlockBody(conditionCodes, data, ptrData, hashPtrPrevBlock);
				break;
			} catch(Exception e) {
				continue;
			}
		}
		
		
		String[] args = {"5001"};
		int n_patient;
		int i_real_patient;
		int n_hospital;
		int i_real_hospital;
		CryptoData[] key1 = new CryptoDataArray[2];
		CryptoData[] key2 = new CryptoDataArray[2];
		
		//change the output of the and and OR to work together
		//patient proof
		n_patient = BlockChain.patients.size(); //patients is the OR
		i_real_patient = (int) (Math.random() * (n_patient - 1)); //n-1 will be the proof for the current block
		
		System.out.println(n_patient + " " + i_real_patient);
		CryptoData[] patientOr = OR_Fiat_Shamir_AADProverBasicECSchnorrORExample.prover(args, n_patient, i_real_patient);
		key1[0] = new CryptoDataArray(patientOr);
		
		CryptoData[] patientAND = AND_Fiat_Shamir_AABProverBasicDLSchnorrANDExample.prover(args, 2);; //AND	call;
		key1[1] = new CryptoDataArray(patientAND);
		System.out.println("patient proof works");
		
		
		
		//hospital proof
		n_hospital = BlockChain.hospitals.size(); //hospitals is the OR
		i_real_hospital = (int) (Math.random() * (n_hospital - 1)); //n-1 will be the proof for the current block
		
		System.out.println(n_hospital + " " + i_real_hospital);
		CryptoData[] hospitalOr = OR_Fiat_Shamir_AADProverBasicECSchnorrORExample.prover(args, n_hospital, i_real_hospital);
		key2[0] = new CryptoDataArray(hospitalOr);
		
		CryptoData[] hospitalAND = AND_Fiat_Shamir_AABProverBasicDLSchnorrANDExample.prover(args, 2);; //AND call;
		key2[1] = new CryptoDataArray(hospitalAND);
		System.out.println("hospital proof works");
		
		
		
		
		
		/*
		//hospital proof
		n_hospital = BlockChain.hospitals.size(); //hospitals is the OR, the extra is for the AND
		i_real_hospital = (int) (Math.random() * (n_hospital - 1)); //n-1 will be the proof for the current block
		
		System.out.println(n_hospital + " " + i_real_hospital);
		key2 = AND_OR_Fiat_Shamir_AADProverBasicECSchnorrORExample.prover(args, n_hospital, i_real_hospital);
		System.out.println("hospital proof works");
		
		header = new BlockHeader(key1, key2); */
		
		/*			
		while(true) {
			try { 
				n = BlockChain.patients.size(); //patients size, hospital size, and num of blocks are all the same
				i_real = (int) (Math.random() * n);

				key1 = Working_AADProverBasicECSchnorrORExample.prover(arr, n, i_real);
				worked1 = Working_AADVerifierBasicECSchnorrORExample.verifier(arr, n, i_real);
				
				if(worked1) {
					key2 = Working_AADProverBasicECSchnorrORExample.prover(arr, n, i_real);
					worked2 = Working_AADVerifierBasicECSchnorrORExample.verifier(arr, n, i_real);
					
					if(worked2) {
						header = new BlockHeader(key1, key2);
						break;
					}
				}
				continue;
			} catch (Exception e) {
				continue;
			}
		}*/
	}

	public BlockHeader getHeader() {
		return header;
	}

	public void setHeader(BlockHeader header) {
		this.header = header;
	}

	public BlockBody getBody() {
		return body;
	}

	public void setBody(BlockBody body) {
		this.body = body;
	}

	public String getHash() {
		return hash;
	}

	public void setHash(String hash) {
		this.hash = hash;
	}
	
	public Patient getPatient() {
		return getBody().getPatient();
	}
	
	public void setPatient(Patient patient) {
		getBody().setPatient(patient);
	}
	
	public Hospital getHospital() {
		return getBody().getHospital();
	}
	
	public void setHospital(Hospital hospital) {
		getBody().setHospital(hospital);
	}
}
