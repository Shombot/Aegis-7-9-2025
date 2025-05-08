package poly;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Enumeration;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import poly.PolyLock;
import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class PolyLockTester2 {
	public static void main(String[] args) {


		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

		SecureRandom rand = new SecureRandom();
		ECCurve c = spec.getCurve();
		ECPoint g = spec.getG();
		BigInteger order = c.getOrder();
		ECPoint h = g.multiply(ZKToolkit.random(order, rand));
		
		BigInteger key = ZKToolkit.random(order, rand);
		
		BigInteger invKey = key.modInverse(order);
		
		BigInteger invKey2 = key.modPow(order.subtract(BigInteger.valueOf(2)), order);
		System.out.println(invKey);
		System.out.println(invKey2);
		
		
		ECPoint q = g.multiply(key);
		
		System.out.println(q.add(g.multiply(invKey)).negate().normalize());
		System.out.println(g);
		
	}

}
