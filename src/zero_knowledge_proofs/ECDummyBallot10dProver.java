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

public class ECDummyBallot10dProver extends ZKPProtocol {
	//This is a proof required for Orbit Dummy ballot part 1.  It proves the following relation exists:  g_1^x, g_2^x*h_2^r, g_2^r

	@Override
	public CryptoData initialComm(CryptoData input, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CryptoData initialComm(CryptoData publicInput, CryptoData secrets, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		//pubIn = [g_1^x, C_{1,1}, C_{1,2}]
		//secIn = [rp1, rp2, x, r]
		//envIn = [g_1, g_2, h_2]
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
		a[0] = new ECPointData(envInPoint[0].multiply(secInInt[0]));
		a[1] = new ECPointData(envInPoint[1].multiply(secInInt[0]).add(envInPoint[2].multiply(secInInt[1])));
		a[2] = new ECPointData(envInPoint[1].multiply(secInInt[1]));
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
		a[0] = new ECPointData(envInPoint[0].multiply(secInInt[0]).subtract(pubInPoint[0].multiply(challenge)));
		a[1] = new ECPointData(envInPoint[1].multiply(secInInt[0]).add(envInPoint[2].multiply(secInInt[1])).subtract(pubInPoint[1].multiply(challenge)));
		a[2] = new ECPointData(envInPoint[1].multiply(secInInt[1]).subtract(pubInPoint[2].multiply(challenge)));
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
		// TODO Auto-generated method stub
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
		ECPointWrapper[] envInPoint = new ECPointWrapper[envIn.length];
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
		
		ECPointWrapper[] left = new ECPointWrapper[3];
		ECPointWrapper[] right = new ECPointWrapper[3];
		
		left[0] = envInPoint[0].multiply(zInInt[0]);
		left[1] = envInPoint[1].multiply(zInInt[0]).add(envInPoint[2].multiply(zInInt[1]));
		left[2] = envInPoint[1].multiply(zInInt[1]);
		
		for(int i = 0; i < right.length; i++) {
			right[i] = aInPoint[i].add(pubInPoint[i].multiply(challenge));
			if (!right[i].equals(left[i])) {
				System.out.printf("Failed on statement %d in %s\n", i, this.getClass().getName());
				return false;
			}
		}
		
		
		return true;
	}
}
