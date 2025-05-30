package curve_wrapper;

import java.math.BigInteger;

import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerFieldElement;

public class Ed25519Curve implements ECCurveWrapper {

	private Curve curve;
	
	public Ed25519Curve(Curve curve) {
		this.curve = curve;
	}
	
	@Override
	public ECPointWrapper createPoint(BigInteger x, BigInteger y) {
		byte[] temp = new BigIntegerFieldElement(curve.getField(), y).toByteArray();
		return new Ed25519Point(curve.createPoint(temp, true));
	}

	@Override
	public ECPointWrapper decodePoint(byte[] encodedPoint) {
		return new Ed25519Point(curve.createPoint(encodedPoint, true));
	}

	@Override
	public BigInteger getA() {
		return null;
	}

	@Override
	public BigInteger getB() {
		return null;
	}

	@Override
	public BigInteger getCofactor() {
		return BigInteger.valueOf(8);
	}

	@Override
	public int getCoordinateSystem() {
		return 0;
	}

	@Override
	public ECPointWrapper getInfinity() {
		return new Ed25519Point(curve.getZero(GroupElement.Representation.P3));
	}

	@Override
	public BigInteger getOrder() {
		return BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
	}

	@Override
	public ECPointWrapper validatePoint(BigInteger x, BigInteger y) {
		return null;
	}

	@Override
	public ECPointWrapper importPoint(ECPointWrapper point) {
		return null;
	}
	
	@Override
	public boolean equals(ECCurveWrapper other) {
		if(this == other) return true;
		Object otherC = other.getCurve();
		if(otherC instanceof Curve) {
			if(this.curve.equals(other.getCurve())) {
				return true;
			}
		}
		return false;
			
			
	}

	@Override
	public Object getCurve() {
		return curve;
	}

}
