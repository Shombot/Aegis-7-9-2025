package zero_knowledge_proofs;

import java.math.BigInteger;

import zero_knowledge_proofs.CryptoData.CryptoData;

public abstract class PedersenCommitment {

	abstract public boolean verifyCommitment(BigInteger message, BigInteger keys, CryptoData environment);

	abstract public PedersenCommitment multiplyCommitment(PedersenCommitment cmt, CryptoData environment);
	abstract public PedersenCommitment multiplyShiftedCommitment(PedersenCommitment cmt, int lShift, CryptoData environment);
	
	abstract public String toString64();

	
}
