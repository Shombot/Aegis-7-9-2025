package zero_knowledge_proofs;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import curve_wrapper.ECCurveWrapper;
import curve_wrapper.ECPointWrapper;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class ECDummyBallot10bProver extends ZKPProtocol {
	//This proof is required for the ORBIT protocol.  It proves the relationship that two ciphertexts hide m_1 and m_2 and a third point is g^(m_1 + m_2) (with potentially different generators and keys)  
	@Override
	public CryptoData initialComm(CryptoData input, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CryptoData initialComm(CryptoData publicInput, CryptoData secrets, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		//C_{1,1} is the cipher portion of ciphertext C_1.  C_{1,2} is the ephemeral key portion.
		//Public Inputs:  [I, C_{1,1}, C_{1,2}, C_{2, 1}, C_{2,2}]
		//Secrets:        [rp1, rp2, rp3, rp4, x, k, r1, r2]
		//Environment:    [(curve, g_1), g_2, h_2, g_3, h_3]
		
		CryptoData[] pubIn = publicInput.getCryptoDataArray();
		CryptoData[] secIn = secrets.getCryptoDataArray();
		CryptoData[] envIn = environment.getCryptoDataArray();
		
//		ECPointWrapper[] pubInPoint = new ECPointWrapper[pubIn.length];
		BigInteger[] secInInt = new BigInteger[secIn.length/2];
		ECCurveWrapper curve = envIn[0].getECCurveData();
		ECPointWrapper[] envInPoint = new ECPointWrapper[envIn.length];
		for(int i = 0; i < secInInt.length; i++) {
			secInInt[i] = secIn[i].getBigInt();	
		}
		for(int i = 0; i < envInPoint.length; i++) {
			envInPoint[i] = envIn[i].getECPointData(curve);
		}
		
		CryptoData[] a = new CryptoData[pubIn.length];
		a[0] = new ECPointData(envInPoint[0].multiply(secInInt[0].add(secInInt[1]).mod(curve.getOrder())));
		a[1] = new ECPointData(envInPoint[1].multiply(secInInt[0]).add(envInPoint[2].multiply(secInInt[2])));
		a[2] = new ECPointData(envInPoint[1].multiply(secInInt[2]));
		a[3] = new ECPointData(envInPoint[3].multiply(secInInt[1]).add(envInPoint[4].multiply(secInInt[3])));
		a[4] = new ECPointData(envInPoint[3].multiply(secInInt[3]));
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
		//Secrets:        [z1, z2, z3, z4]
		CryptoData[] pubIn = publicInput.getCryptoDataArray();
		CryptoData[] secIn = secrets.getCryptoDataArray();
		CryptoData[] envIn = environment.getCryptoDataArray();
		
		ECPointWrapper[] pubInPoint = new ECPointWrapper[pubIn.length];
		BigInteger[] secInInt = new BigInteger[secIn.length];
		ECCurveWrapper curve = envIn[0].getECCurveData();
		ECPointWrapper[] envInPoint = new ECPointWrapper[envIn.length];
		for(int i = 0; i < pubInPoint.length; i++) {
			pubInPoint[i] = pubIn[i].getECPointData(curve);	
		}
		for(int i = 0; i < secInInt.length; i++) {
			secInInt[i] = secIn[i].getBigInt();	
		}
		for(int i = 0; i < envInPoint.length; i++) {
			envInPoint[i] = envIn[i].getECPointData(curve);
		}
		
		CryptoData[] a = new CryptoData[pubIn.length];
		a[0] = new ECPointData(envInPoint[0].multiply(secInInt[0].add(secInInt[1]).mod(curve.getOrder())).subtract(pubInPoint[0].multiply(challenge)));
		a[1] = new ECPointData(envInPoint[1].multiply(secInInt[0]).add(envInPoint[2].multiply(secInInt[2])).subtract(pubInPoint[1].multiply(challenge)));
		a[2] = new ECPointData(envInPoint[1].multiply(secInInt[2]).subtract(pubInPoint[2].multiply(challenge)));
		a[3] = new ECPointData(envInPoint[3].multiply(secInInt[1]).add(envInPoint[4].multiply(secInInt[3])).subtract(pubInPoint[3].multiply(challenge)));
		a[4] = new ECPointData(envInPoint[3].multiply(secInInt[3]).subtract(pubInPoint[4].multiply(challenge)));
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
		
		BigInteger[] secInInt = new BigInteger[secIn.length];
		ECCurveWrapper curve = envIn[0].getECCurveData();
		BigInteger order = curve.getOrder();
		for(int i = 0; i < secInInt.length; i++) {
			secInInt[i] = secIn[i].getBigInt();	
		}
		CryptoData[] z = new CryptoData[secInInt.length/2];
		
		for(int i = 0; i < z.length; i++) {
			z[i] = new BigIntData(secInInt[i].add(challenge.multiply(secInInt[i+z.length])).mod(order));
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
		
		return secrets;
	}

	@Override
	public boolean verifyResponse(CryptoData input, CryptoData a, CryptoData z, BigInteger challenge,
			CryptoData environment) {

		CryptoData[] pubIn = input.getCryptoDataArray();
		CryptoData[] envIn = environment.getCryptoDataArray();
		CryptoData[] aIn = a.getCryptoDataArray();
		CryptoData[] zIn = z.getCryptoDataArray();
		
		
		ECPointWrapper[] pubInPoint = new ECPointWrapper[pubIn.length];
		BigInteger[] zInInt = new BigInteger[8];
		ECPointWrapper[] aInPoint = new ECPointWrapper[5];
		ECCurveWrapper curve = envIn[0].getECCurveData();
		BigInteger order = curve.getOrder();
		ECPointWrapper[] envInPoint = new ECPointWrapper[5];
		for(int i = 0; i < pubInPoint.length; i++) {
			pubInPoint[i] = pubIn[i].getECPointData(curve);	
		}
		for(int i = 0; i < envInPoint.length; i++) {
			envInPoint[i] = envIn[i].getECPointData(curve);
		}
		for(int i = 0; i < aIn.length; i++) {
			aInPoint[i] = aIn[i].getECPointData(curve);
		}

		for(int i = 0; i < zIn.length; i++) {
			zInInt[i] = zIn[i].getBigInt();
		}
		
		ECPointWrapper[] left = new ECPointWrapper[5];
		ECPointWrapper[] right = new ECPointWrapper[5];
		
		left[0] = envInPoint[0].multiply(zInInt[0].add(zInInt[1]).mod(order));
		left[1] = envInPoint[1].multiply(zInInt[0]).add(envInPoint[2].multiply(zInInt[2]));
		left[2] = envInPoint[1].multiply(zInInt[2]);
		left[3] = envInPoint[3].multiply(zInInt[1]).add(envInPoint[4].multiply(zInInt[3]));
		left[4] = envInPoint[3].multiply(zInInt[3]);
		boolean verify = true;
		for(int i = 0; i < right.length; i++) {
			right[i] = aInPoint[i].add(pubInPoint[i].multiply(challenge));
			if (!right[i].equals(left[i])) {
				System.out.printf("Failed on statement %d in %s\n", i, this.getClass().getName());
				verify = false;
			}
		}
		
		
		return verify;
	}

}
