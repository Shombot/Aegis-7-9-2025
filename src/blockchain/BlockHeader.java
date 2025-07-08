package blockchain;

import zero_knowledge_proofs.CryptoData.CryptoData;

public class BlockHeader {
	/*
	 * HEADER
	 * hash of this block (hash of everything besides this part) BlockNode
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
	 * condition codes b
	*/
	
	//maybe add a link to the patient and hospital
	private String ptrRegular;
	private CryptoData[] ZKPPatient;
	private CryptoData[] ZKPHospital;
	
	
	//There is no ptrRegular since we add this when we are mining
	public BlockHeader(CryptoData[] ZKPPatient, CryptoData[] ZKPHospital) {
		this.ZKPPatient = ZKPPatient;
		this.ZKPHospital = ZKPHospital;
	}

	public String getPtrRegular() {
		return ptrRegular;
	}

	public void setPtrRegular(String ptrRegular) {
		this.ptrRegular = ptrRegular;
	}

	public CryptoData[] getZKPPatient() {
		return ZKPPatient;
	}

	public void setZKPPatient(CryptoData[] ZKPPatient) {
		this.ZKPPatient = ZKPPatient;
	}

	public CryptoData[] getZKPHospital() {
		return ZKPHospital;
	}

	public void setZKPHospital(CryptoData[] ZKPHospital) {
		this.ZKPHospital = ZKPHospital;
	}
}
