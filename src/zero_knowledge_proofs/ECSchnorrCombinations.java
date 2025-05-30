package zero_knowledge_proofs;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.InputMismatchException;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import curve_wrapper.ECCurveWrapper;
import curve_wrapper.ECPointWrapper;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class ECSchnorrCombinations extends ZKPProtocol {
	private int[][][] structure;
	private int numSecrets;
	private int numGen;
	private int numPub;
	//first dimension is the number of public values
	//second dimension is number of discrete log problems in the term
	//third is which generator and which exponent.
	
	//Examples:  Just Schnorr would be {{{0, 0}}}.  A Pedersen Commitment would be {{{0,0},{1,1}}}.  A Diffie Hellman would be {{{0,0}},{{0, 1}}}.  An Exponential Elgamal Ciphertext would be {{{0, 0},{1,1}},{{0,1}}}
	public ECSchnorrCombinations(int[][][] structure2){
		this.structure = new int[structure2.length][][];
		
		numPub = structure2.length;
		for(int i = 0; i < numPub; i++) {
			if(structure2[i].length == 0) throw new InputMismatchException(String.format("Public value %d has no structure.  Every public value must have at least one generator and one exponent", i));
			structure[i] = new int[structure2[i].length][2];
			for(int j = 0; j < structure[i].length; j++) {
				if(structure2[i][j].length != 2) {
					throw new InputMismatchException(String.format("Term %d, subterm %d has %d values, not 2 (1 generator and 1 exponent).", i, j, structure2[i][j].length));
				}
				//TODO:  Should I check to make sure that every generator index is used?
				if(structure2[i][j][0] < 0) throw new InputMismatchException(String.format("Term %d, generator %d has negative generator index %d", i, j, structure2[i][j][0]));
				structure[i][j][0] = structure2[i][j][0];
				if(structure2[i][j][0] > numGen) numGen = structure2[i][j][0];
				if(structure2[i][j][1] < 0) throw new InputMismatchException(String.format("Term %d, generator %d has negative exponent index %d", i, j, structure2[i][j][1]));
				structure[i][j][1] = structure2[i][j][1];
				if(structure2[i][j][1] > numSecrets) numSecrets = structure2[i][j][1];
			}
		}
		numSecrets++;
		numGen++;
	}
	

	@Override
	public CryptoData initialComm(CryptoData input, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CryptoData initialComm(CryptoData publicInput, CryptoData secrets, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		//pub = [y_0, y_1 ... y_{k_1}]
		//sec = [rp_0, rp_1, ... rp_{k_2}, x_0, x_1 ... x_{k_2}]
		//env = [g_0, g_1 ... g_{k_3}]
		
//		CryptoData[] pubIn = publicInput.getCryptoDataArray();
		CryptoData[] secIn = secrets.getCryptoDataArray();
		CryptoData[] envIn = environment.getCryptoDataArray(); 
		
		ECCurveWrapper curve = envIn[0].getECCurveData();
		
//		ECPointWrapper[] pub = new ECPointWrapper[pubIn.length];
//		for(int i = 0; i < pubIn.length; i++) {
//			pub[i] = pubIn[i].getECPointData(curve);
//		}
		
//		BigInteger[] sec = new BigInteger[secIn.length];
//		for(int i = 0; i < secIn.length; i++) {
//			sec[i] = secIn[i].getBigInt();
//		}
		BigInteger[] sec = new BigInteger[secIn.length/2];
		for(int i = 0; i < secIn.length/2; i++) {
		sec[i] = secIn[i].getBigInt();
	}

		ECPointWrapper[] env = new ECPointWrapper[envIn.length];
		for(int i = 0; i < envIn.length; i++) {
			env[i] = envIn[i].getECPointData(curve);
		}
		
		ECPointWrapper[] a = new ECPointWrapper[numPub];
		
		for(int i = 0; i < numPub; i++) {
			a[i] = curve.getInfinity();
			for(int j = 0; j < structure[i].length; j++) {
//				System.out.printf("a = %d, env = %d, sec = %d, struct = %d,struct[i][j][0] = %d, struct[i][j][1] = %d\n", a.length, env.length, sec.length, structure.length, structure[i][j][0], structure[i][j][1]);
				a[i] = a[i].add(env[structure[i][j][0]].multiply(sec[structure[i][j][1]]));
			}
		}
		
		return new CryptoDataArray(a);
	}

	@Override
	public CryptoData initialCommSim(CryptoData input, BigInteger challenge, CryptoData environment)
			throws MultipleTrueProofException, ArraySizesDoNotMatchException, NoTrueProofException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CryptoData initialCommSim(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment)
			throws MultipleTrueProofException, ArraySizesDoNotMatchException, NoTrueProofException {
		CryptoData[] pubIn = publicInput.getCryptoDataArray();
		CryptoData[] secIn = secrets.getCryptoDataArray();
		CryptoData[] envIn = environment.getCryptoDataArray(); 
		
		ECCurveWrapper curve = envIn[0].getECCurveData();
		
		ECPointWrapper[] pub = new ECPointWrapper[pubIn.length];
		for(int i = 0; i < pubIn.length; i++) {
			pub[i] = pubIn[i].getECPointData(curve);
		}
		
//		BigInteger[] sec = new BigInteger[secIn.length];
//		for(int i = 0; i < secIn.length; i++) {
//			sec[i] = secIn[i].getBigInt();
//		}
		BigInteger[] sec = new BigInteger[secIn.length];
		for(int i = 0; i < secIn.length; i++) {
			sec[i] = secIn[i].getBigInt();
		}

		ECPointWrapper[] env = new ECPointWrapper[envIn.length];
		for(int i = 0; i < envIn.length; i++) {
			env[i] = envIn[i].getECPointData(curve);
		}
		
		ECPointWrapper[] a = new ECPointWrapper[numPub];
		
		for(int i = 0; i < numPub; i++) {
			a[i] = pub[i].multiply(challenge.negate());
			for(int j = 0; j < structure[i].length; j++) {
				ECPointWrapper arg1 = env[structure[i][j][0]];
				BigInteger arg2 = sec[structure[i][j][1]];
				a[i] = a[i].add(arg1.multiply(arg2));
			}
			
		}
		
		return new CryptoDataArray(a);
	}

	@Override
	public CryptoData calcResponse(CryptoData input, BigInteger challenge, CryptoData environment)
			throws NoTrueProofException, MultipleTrueProofException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CryptoData calcResponse(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment) throws NoTrueProofException, MultipleTrueProofException {
//		CryptoData[] pubIn = publicInput.getCryptoDataArray();
		CryptoData[] secIn = secrets.getCryptoDataArray();
		CryptoData[] envIn = environment.getCryptoDataArray(); 
		
		ECCurveWrapper curve = envIn[0].getECCurveData();
		
//		ECPointWrapper[] pub = new ECPointWrapper[pubIn.length];
//		for(int i = 0; i < pubIn.length; i++) {
//			pub[i] = pubIn[i].getECPointData(curve);
//		}
		
		BigInteger[] sec = new BigInteger[secIn.length];
		for(int i = 0; i < secIn.length; i++) {
			sec[i] = secIn[i].getBigInt();
		}

//		ECPointWrapper[] env = new ECPointWrapper[envIn.length];
//		for(int i = 0; i < envIn.length; i++) {
//			env[i] = envIn[i].getECPointData(curve);
//		}
		
		BigInteger[] z = new BigInteger[numSecrets];
		
		for(int i = 0; i < numSecrets; i++) {
			z[i] = sec[i].add(sec[i+numSecrets].multiply(challenge)).mod(curve.getOrder());
		}
		return new CryptoDataArray(z);
	}

	@Override
	public CryptoData simulatorGetResponse(CryptoData input) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CryptoData simulatorGetResponse(CryptoData publicInput, CryptoData secrets) {
		// TODO Auto-generated method stub
		return secrets;
	}

	@Override
	public boolean verifyResponse(CryptoData input, CryptoData a, CryptoData z, BigInteger challenge,
			CryptoData environment) {
		CryptoData[] pubIn = input.getCryptoDataArray();
		CryptoData[] envIn = environment.getCryptoDataArray(); 
		
		ECCurveWrapper curve = envIn[0].getECCurveData();
		
		ECPointWrapper[] pub = new ECPointWrapper[pubIn.length];
		for(int i = 0; i < pubIn.length; i++) {
			pub[i] = pubIn[i].getECPointData(curve);
		}
		
		ECPointWrapper[] env = new ECPointWrapper[envIn.length];
		for(int i = 0; i < envIn.length; i++) {
			env[i] = envIn[i].getECPointData(curve);
		}
		CryptoData[] aInUnpacked = a.getCryptoDataArray();
		CryptoData[] zInUnpacked = z.getCryptoDataArray();
		BigInteger[] zIn = new BigInteger[numSecrets];
		for(int i = 0; i < zIn.length; i++) {
			zIn[i] = zInUnpacked[i].getBigInt();
		}
		ECPointWrapper[] aIn = new ECPointWrapper[numPub];
		boolean verify = true;
		for(int i = 0; i < numPub; i++) {
			aIn[i] = aInUnpacked[i].getECPointData(curve);
			ECPointWrapper left = curve.getInfinity();
			ECPointWrapper right = curve.getInfinity();
			for(int j = 0; j < structure[i].length; j++) {
				left = left.add(env[structure[i][j][0]].multiply(zIn[structure[i][j][1]]));
			}
			right = aIn[i].add(pub[i].multiply(challenge));
			if(!left.equals(right)) {
				System.out.println(String.format("On %d:  %s != %s", i, left.normalize(), right.normalize()));
				
				verify = false;
			}
		}
		
		return verify;
	}
}
