package examples;

import java.math.BigInteger;
import java.security.SecureRandom;

import curve_wrapper.ECCurveWrapper;
import curve_wrapper.Ed25519Curve;
import curve_wrapper.Ed25519Point;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerFieldElement;
import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import zero_knowledge_proofs.ECPedersenCommitment;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;



public class Ed25519Test {
	public static void main(String[] args) {

		EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName("ed25519");
		GroupElement gW = spec.getB(); 
		System.out.println(gW);
		BigInteger temp = BigInteger.valueOf(5);
		int[] temp2 = new int[10];
		temp2[0] = 5;
		BigIntegerFieldElement blah = new BigIntegerFieldElement(gW.getCurve().getField(), temp);
		Ed25519FieldElement blah2 = new Ed25519FieldElement(gW.getCurve().getField(), temp2);
		temp2[0] = 4;
		Ed25519FieldElement blah3 = new Ed25519FieldElement(gW.getCurve().getField(), temp2);
		GroupElement inf = gW.scalarMultiply(new byte[32]);
		System.out.println(inf);
		SecureRandom rand = new SecureRandom();
		
		Ed25519Point g = new Ed25519Point(gW);
		BigInteger order = g.getCurve().getOrder();
		Ed25519Point h = g.multiply(ZKToolkit.random(order, rand));

		ECCurveWrapper c = g.getCurve();
		
		CryptoData env = new CryptoDataArray(new CryptoData[] {new ECCurveData(c,g), new ECPointData(h)});
		
		BigInteger m = BigInteger.valueOf(50);
//				ZKToolkit.random(order, rand);
		BigInteger r = BigInteger.valueOf(500);
//				ZKToolkit.random(order, rand);
		
		ECPedersenCommitment comm = new ECPedersenCommitment(m, r, env);
		System.out.println("Comm test = " + comm.verifyCommitment(m, r, env));
		
		Ed25519Point gpg = g;
		int num = 5000;
		for(int i = 1; i < num; i++) {
			gpg = gpg.add(gpg);
		}
		Ed25519Point gtg = g.multiply(BigInteger.ONE.shiftLeft(num-1));
		System.out.println(gpg.equals(gtg));
	}
}
