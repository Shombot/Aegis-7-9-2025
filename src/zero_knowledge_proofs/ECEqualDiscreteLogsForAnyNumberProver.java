package zero_knowledge_proofs;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import curve_wrapper.ECCurveWrapper;
import curve_wrapper.ECPointWrapper;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class ECEqualDiscreteLogsForAnyNumberProver extends ZKPProtocol {
	private int k;
	public ECEqualDiscreteLogsForAnyNumberProver(int numValues) {
		this.k = numValues;
	}
	//input = [y_g, y_h, r, x]
	@Override
	public CryptoData initialComm(CryptoData input, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		return null;
	}

	//input = [y_g, y_h, z]
	@Override
	public CryptoData initialCommSim(CryptoData input, BigInteger challenge, CryptoData environment)
			throws MultipleTrueProofException, ArraySizesDoNotMatchException {
		return null;
	}

	@Override
	public CryptoData calcResponse(CryptoData input, BigInteger challenge, CryptoData environment)
			throws NoTrueProofException, MultipleTrueProofException {
		return null;
	}

	@Override
	public CryptoData simulatorGetResponse(CryptoData input) {
		return null;
	}

	@Override
	public boolean verifyResponse(CryptoData input, CryptoData a, CryptoData z, BigInteger challenge,
			CryptoData environment) {
		CryptoData[] e = environment.getCryptoDataArray();
		CryptoData[] resp = z.getCryptoDataArray();
		CryptoData[] i = input.getCryptoDataArray();
		CryptoData[] a_pack = a.getCryptoDataArray();
		
		ECCurveWrapper c = e[0].getECCurveData();
		BigInteger zNumber = resp[0].getBigInt();
		for(int j = 0; j < k; j++) {
			ECPointWrapper g = e[j].getECPointData(c);
			ECPointWrapper y_g = i[j].getECPointData(c);
			ECPointWrapper a_g = a_pack[j].getECPointData(c);
			if(!(y_g.multiply(challenge).add(a_g)).equals(g.multiply(zNumber))) {
				return false;
			}
		}
		return true;

	}
	//pub = [h_1, h_2, ... h_k]
	//sec = [rp, x]
	//env = [g_1, g_2, ... g_k]
	@Override 
	public CryptoData initialComm(CryptoData publicInput, CryptoData secrets, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		ECPointWrapper[] data = new ECPointWrapper[k];
		CryptoData[] e = environment.getCryptoDataArray();
//		CryptoData[] pI = publicInput.getCryptoDataArray();
		CryptoData[] s = secrets.getCryptoDataArray();
		ECCurveWrapper c = e[0].getECCurveData();
		BigInteger r = s[0].getBigInt();
		for(int i = 0; i < k; i++) {
			ECPointWrapper g = e[i].getECPointData(c);
			data[i] = g.multiply(r);
		}
		

		CryptoData toReturn = new CryptoDataArray(data);
		return toReturn;
	}

	@Override
	public CryptoData initialCommSim(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment)
			throws MultipleTrueProofException, ArraySizesDoNotMatchException, NoTrueProofException {
		ECPointWrapper[] data = new ECPointWrapper[k];
		CryptoData[] i = publicInput.getCryptoDataArray();
		CryptoData[] s = secrets.getCryptoDataArray();
		CryptoData[] e = environment.getCryptoDataArray();		//(y, z) 
		ECCurveWrapper c = e[0].getECCurveData();
		BigInteger z = s[0].getBigInt();
		for(int j = 0; j < k; j++) {
			ECPointWrapper g = e[j].getECPointData(c);
			ECPointWrapper y_g = i[j].getECPointData(c);
			data[j] = g.multiply(z).add(y_g.multiply(challenge.negate()));
		}
		//a = g^z * y^(-c)
		//System.out.printf("c = %s\ninputs = %s\n", challenge.toString(16), input);
		
		CryptoData toReturn = new CryptoDataArray(data);
		return toReturn;
	}

	@Override
	public CryptoData calcResponse(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment) throws NoTrueProofException, MultipleTrueProofException {
		BigInteger[] array = new BigInteger[1];
//		CryptoData[] i = publicInput.getCryptoDataArray();
		CryptoData[] s = secrets.getCryptoDataArray();
		CryptoData[] e = environment.getCryptoDataArray();

		BigInteger x = s[1].getBigInt();
		BigInteger r = s[0].getBigInt();
		array[0] = (r.add(x.multiply(challenge))).mod(e[0].getECCurveData().getOrder());
		//System.out.printf("P:\t%s ?= %s\n", ((i[1].modPow(challenge, e[1]).multiply(e[0].modPow(i[2], e[1]))).mod(e[1])), e[0].modPow(array[0], e[1]));
		
		//System.out.printf("P:\tg = %s\nP:\th = %s\nP:\tp = %s\nP:\tr = %s\nP:\tx = %s\nP:\ty = %s\nP:\tz = %s\nP:\tc = %s\n",e[0],e[1],e[1],i[2],i[0],i[1], array[0], challenge);
		CryptoData toReturn = new CryptoDataArray(array);
		return toReturn;
	}

	@Override
	public CryptoData simulatorGetResponse(CryptoData publicInput, CryptoData secrets) {
		CryptoData[] in = secrets.getCryptoDataArray();
		BigInteger[] out = new BigInteger[1];
		out[0] = in[0].getBigInt();
		return new CryptoDataArray(out);
	}
}
