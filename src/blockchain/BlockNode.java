package blockchain;

import java.io.IOException;

import examples.Fiat_Shamir_AADProverBasicECSchnorrORExample;
import examples.Returning_AADProverBasicECSchnorrORExample;
import examples.Returning_AADVerifierBasicECSchnorrORExample;
import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.CryptoData.CryptoData;

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
		
		
		String[] arr = {"5001"};
		int n;
		int i_real;
		boolean worked1;
		boolean worked2;
		CryptoData[] key1;
		CryptoData[] key2;
		
		n = BlockChain.patients.size(); //patients size, hospital size, and num of blocks are all the same
		i_real = (int) (Math.random() * n);
		
		System.out.println(n + " " + i_real);
		key1 = Fiat_Shamir_AADProverBasicECSchnorrORExample.prover(arr, n, i_real);
		System.out.println("p1 works");
		key2 = Fiat_Shamir_AADProverBasicECSchnorrORExample.prover(arr, n, i_real);
		System.out.println("p2 works");
		
		header = new BlockHeader(key1, key2);
		
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
