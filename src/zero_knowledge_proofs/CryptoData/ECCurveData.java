package zero_knowledge_proofs.CryptoData;

import java.math.BigInteger;
import java.security.spec.EllipticCurve;
import java.util.Base64;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;

import curve_wrapper.ECCurveWrapper;
import curve_wrapper.ECPointWrapper;

public final class ECCurveData extends CryptoData {
	/**
	 * 
	 */
	private static final long serialVersionUID = 5968736215439976858L;
	private ECCurveWrapper c;
	private ECPointWrapper g;
	
	public ECCurveData(ECCurveWrapper c, ECPointWrapper g)
	{
		this.c = c;
		if(!g.isNormalized())
			g = g.normalize();
		this.g = g;
	}
	@Override
	public CryptoData[] getCryptoDataArray() {
		return null;
	}
	
	@Override
	public ECCurveWrapper getECCurveData() {
		 return c;
	}
	@Override
	public ECPointWrapper getECPointData(ECCurveWrapper c) {
		if(this.c == c)
			return g;
		else return c.importPoint(g);
	}
	
	@Override
	public int size() {
		return 1;
	}

	@Override
	public String toString()
	{
		return String.format("y^2 = x^3 + %sx + %s, G = (%s, %s)", c.getA().toString(16), c.getB().toString(16), g.getAffineXCoord().toString(16), g.getAffineYCoord().toString(16));
	}
	@Override
	public String toString64()
	{
		return String.format("y^2 = x^3 + %sx + %s, G = (%s, %s)", Base64.getEncoder().encodeToString(c.getA().toByteArray()), Base64.getEncoder().encodeToString(c.getB().toByteArray()), Base64.getEncoder().encodeToString(g.getAffineXCoord().toByteArray()), Base64.getEncoder().encodeToString(g.getAffineYCoord().toByteArray()));
	}
	@Override
	public byte[] getBytes() {
		// TODO Auto-generated method stub
		return g.getEncoded(true);
	}
	@Override
	public boolean equals(Object o) {
		ECCurveData other = (ECCurveData) o;
		return (c.equals(other.c)) && (g.equals(other.g));
	}
}
