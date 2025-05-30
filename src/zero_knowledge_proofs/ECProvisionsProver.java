package zero_knowledge_proofs;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import curve_wrapper.ECCurveWrapper;
import curve_wrapper.ECPointWrapper;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class ECProvisionsProver extends ZKPProtocol {
	//[0      , 1         , 2   , 3  , 4  , 5  , 6  , 7  , 8  , 9  , 10 , 11 , 12 ]
	//[account, public key, xhat, v_i, t_i, s_i, u_1, u_2, u_3, u_4, u_5, u_6, c_f]
	@Override
	public CryptoData initialComm(CryptoData input, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		CryptoData[] inputs = input.getCryptoDataArray();
		CryptoData[] env = environment.getCryptoDataArray();
		ECCurveWrapper c = env[0].getECCurveData();
		ECPointWrapper b = inputs[0].getECPointData(c);
		ECPointWrapper y = inputs[1].getECPointData(c);
		BigInteger u_1 = inputs[6].getBigInt();
		BigInteger u_2 = inputs[7].getBigInt();
		BigInteger u_3 = inputs[8].getBigInt();
		BigInteger u_4 = inputs[9].getBigInt();
		BigInteger u_5 = inputs[10].getBigInt();
		BigInteger u_6 = inputs[11].getBigInt();
		BigInteger c_f = inputs[12].getBigInt();
		ECPointWrapper g = env[0].getECPointData(c);
		ECPointWrapper h = env[1].getECPointData(c);
		ECPointWrapper[] a = new ECPointWrapper[5];
		//a format: [a_1, a_2, a_3, binA_0, binA_1]
		
		boolean s = inputs[5].getBigInt().equals(BigInteger.ONE);
		a[0] = (b.multiply(u_1).add(h.multiply(u_2)));
		a[1] = (y.multiply(u_1).add(h.multiply(u_3)));
		a[2] = (g.multiply(u_4).add(h.multiply(u_3)));
		
		
		//y^s * h^t
		a[3] = h.multiply(u_5);
		if(s) a[3] = (a[3].add(y.multiply(c_f.negate())));

		a[4] = h.multiply(u_6);
		if(!s) a[4] = (a[4].add(y.multiply(c_f)));
		
		return new CryptoDataArray(a);
	}

	//unused, not needed
	//[account, public key, 
	@Override
	public CryptoData initialCommSim(CryptoData input, BigInteger challenge, CryptoData environment)
			throws MultipleTrueProofException, ArraySizesDoNotMatchException {
		
		
		return null;
	}

	//[0      , 1         , 2   , 3  , 4  , 5  , 6  , 7  , 8  , 9  , 10 , 11 , 12 ]
	//[account, public key, xhat, v_i, t_i, s_i, u_1, u_2, u_3, u_4, u_5, u_6, c_f]
	@Override
	public CryptoData calcResponse(CryptoData input, BigInteger challenge, CryptoData environment)
			throws NoTrueProofException, MultipleTrueProofException {
		CryptoData[] inputs = input.getCryptoDataArray();
		CryptoData[] env = environment.getCryptoDataArray();
		
		ECCurveWrapper c = env[0].getECCurveData();
		BigInteger xhat = inputs[2].getBigInt();
		BigInteger v = inputs[3].getBigInt();
		BigInteger t = inputs[4].getBigInt();
//		BigInteger s = inputs[5].getBigInt();
		BigInteger u_1 = inputs[6].getBigInt();
		BigInteger u_2 = inputs[7].getBigInt();
		BigInteger u_3 = inputs[8].getBigInt();
		BigInteger u_4 = inputs[9].getBigInt();
		BigInteger u_5 = inputs[10].getBigInt();
		BigInteger u_6 = inputs[11].getBigInt();
		BigInteger c_f = inputs[12].getBigInt();
		BigInteger order = c.getOrder();
		boolean s = inputs[5].getBigInt().equals(BigInteger.ONE);
		//r = [r_s, r_v, r_t, r_x, c_1, r_0, r_1]
		BigInteger[] response = new BigInteger[7];
		if(s) response[0] = u_1.add(challenge).mod(order);
		else response[0] = u_1;
		
		response[1] = (u_2.add(challenge.multiply(v))).mod(order);
		response[2] = (u_3.add(challenge.multiply(t))).mod(order);
		response[3] = (u_4.add(challenge.multiply(xhat))).mod(order);
		
		if(s) response[4] = ((challenge.subtract(c_f))).mod(order);
		else  response[4] = c_f;

		//y^s * h^t
		response[5] = (u_5.add((challenge.subtract(response[4])).multiply(t))).mod(order);
		response[6] = (u_6.add(response[4].multiply(t))).mod(order);
		
		return new CryptoDataArray(response);
	}

	//not used
	@Override
	public CryptoData simulatorGetResponse(CryptoData input) {
		// TODO Auto-generated method stub
		return null;
	}
	//        [0      , 1         , 2  , 3  ]
	//input:  [account, public key, p_i, l_i]
	@Override
	public boolean verifyResponse(CryptoData input, CryptoData a, CryptoData z, BigInteger challenge, CryptoData environment) {
		
		
		CryptoData[] inputs = input.getCryptoDataArray();
		CryptoData[] env = environment.getCryptoDataArray();
		CryptoData[] resp = z.getCryptoDataArray();
		CryptoData[] init = a.getCryptoDataArray();
		
		ECCurveWrapper c = env[0].getECCurveData();
				
		ECPointWrapper b = inputs[0].getECPointData(c);
		ECPointWrapper y = inputs[1].getECPointData(c);
		ECPointWrapper pComm = inputs[2].getECPointData(c);
		ECPointWrapper lComm = inputs[3].getECPointData(c);
		
		ECPointWrapper g = env[0].getECPointData(c);
		ECPointWrapper h = env[1].getECPointData(c);
		
		BigInteger r_s = resp[0].getBigInt();
		BigInteger r_v = resp[1].getBigInt();
		BigInteger r_t = resp[2].getBigInt();
		BigInteger r_x = resp[3].getBigInt();
		BigInteger c_1 = resp[4].getBigInt();
		BigInteger r_0 = resp[5].getBigInt();
		BigInteger r_1 = resp[6].getBigInt();
		
		ECPointWrapper a_1 = init[0].getECPointData(c);
		ECPointWrapper a_2 = init[1].getECPointData(c);
		ECPointWrapper a_3 = init[2].getECPointData(c);
		ECPointWrapper binA_0 = init[3].getECPointData(c);
		ECPointWrapper binA_1 = init[4].getECPointData(c);
		
		//resp:  [r_s, r_v, r_t, r_x]
		ECPointWrapper s1L = (b.multiply(r_s).add(h.multiply(r_v)));
		ECPointWrapper s1R = (pComm.multiply(challenge).add(a_1));
		
		ECPointWrapper s2L = (y.multiply(r_s).add(h.multiply(r_t)));
		ECPointWrapper s2R = (lComm.multiply(challenge).add(a_2));
		
		ECPointWrapper s3L = (g.multiply(r_x).add(h.multiply(r_t)));
		ECPointWrapper s3R = (lComm.multiply(challenge).add(a_3));

		//a = [a_1, a_2, a_3, binA_0, binA_1]
		//r = [r_s, r_v, r_t, r_x, c_1, r_0, r_1]
		
		//y^s * h^t
		ECPointWrapper s4L = h.multiply(r_0);
		ECPointWrapper s4R = (binA_0.add(lComm.multiply(challenge.subtract(c_1))));
				
		ECPointWrapper s5L = h.multiply(r_1);
		ECPointWrapper s5R = (binA_1.add((lComm.add(y.negate())).multiply(c_1)));
		boolean toReturn = (s1L.equals(s1R) && s2L.equals(s2R) && s3L.equals(s3R) && s4L.equals(s4R) && s5L.equals(s5R));
		
		return toReturn;
	}

	@Override
	public CryptoData initialComm(CryptoData publicInput, CryptoData secrets, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		CryptoData[] inputs = publicInput.getCryptoDataArray();
		CryptoData[] sU = secrets.getCryptoDataArray();
		CryptoData[] env = environment.getCryptoDataArray();
		ECCurveWrapper c = env[0].getECCurveData();
		ECPointWrapper b = inputs[0].getECPointData(c);
		ECPointWrapper y = inputs[1].getECPointData(c);
		BigInteger u_1 = sU[4].getBigInt();
		BigInteger u_2 = sU[5].getBigInt();
		BigInteger u_3 = sU[6].getBigInt();
		BigInteger u_4 = sU[7].getBigInt();
		BigInteger u_5 = sU[8].getBigInt();
		BigInteger u_6 = sU[9].getBigInt();
		BigInteger c_f = sU[10].getBigInt();
		ECPointWrapper g = env[0].getECPointData(c);
		ECPointWrapper h = env[1].getECPointData(c);
		ECPointWrapper[] a = new ECPointWrapper[5];
		//a format: [a_1, a_2, a_3, binA_0, binA_1]
		
		boolean s = sU[3].getBigInt().equals(BigInteger.ONE);
		a[0] = (b.multiply(u_1).add(h.multiply(u_2)));
		a[1] = (y.multiply(u_1).add(h.multiply(u_3)));
		a[2] = (g.multiply(u_4).add(h.multiply(u_3)));
		
		
		//y^s * h^t
		a[3] = h.multiply(u_5);
		if(s) a[3] = (a[3].add(y.multiply(c_f.negate())));

		a[4] = h.multiply(u_6);
		if(!s) a[4] = (a[4].add(y.multiply(c_f)));
		
		return new CryptoDataArray(a);
	}

	@Override
	public CryptoData initialCommSim(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment)
			throws MultipleTrueProofException, ArraySizesDoNotMatchException, NoTrueProofException {
		return null;
	}

	@Override
	public CryptoData calcResponse(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment) throws NoTrueProofException, MultipleTrueProofException {
		CryptoData[] sU = secrets.getCryptoDataArray();
		CryptoData[] env = environment.getCryptoDataArray();
		
		ECCurveWrapper c = env[0].getECCurveData();
		BigInteger xhat = sU[0].getBigInt();
		BigInteger v = sU[1].getBigInt();
		BigInteger t = sU[2].getBigInt();
//		BigInteger s = sU[3].getBigInt();
		BigInteger u_1 = sU[4].getBigInt();
		BigInteger u_2 = sU[5].getBigInt();
		BigInteger u_3 = sU[6].getBigInt();
		BigInteger u_4 = sU[7].getBigInt();
		BigInteger u_5 = sU[8].getBigInt();
		BigInteger u_6 = sU[9].getBigInt();
		BigInteger c_f = sU[10].getBigInt();
		BigInteger order = c.getOrder();
		boolean s = sU[3].getBigInt().equals(BigInteger.ONE);
		//r = [r_s, r_v, r_t, r_x, c_1, r_0, r_1]
		BigInteger[] response = new BigInteger[7];
		if(s) response[0] = u_1.add(challenge).mod(order);
		else response[0] = u_1;
		
		response[1] = (u_2.add(challenge.multiply(v))).mod(order);
		response[2] = (u_3.add(challenge.multiply(t))).mod(order);
		response[3] = (u_4.add(challenge.multiply(xhat))).mod(order);
		
		if(s) response[4] = ((challenge.subtract(c_f))).mod(order);
		else  response[4] = c_f;

		//y^s * h^t
		response[5] = (u_5.add((challenge.subtract(response[4])).multiply(t))).mod(order);
		response[6] = (u_6.add(response[4].multiply(t))).mod(order);
		
		return new CryptoDataArray(response);
	}

	@Override
	public CryptoData simulatorGetResponse(CryptoData publicInput, CryptoData secrets) {
		return null;
	}
}
