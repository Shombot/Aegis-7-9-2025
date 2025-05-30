package curve_wrapper;

import java.math.BigInteger;
import java.util.InputMismatchException;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class BouncyCastleCurve implements ECCurveWrapper {
	final private ECCurve c;
	public BouncyCastleCurve(ECCurve c) {
		this.c = c;
	}
	@Override
	public ECPointWrapper createPoint(BigInteger x, BigInteger y) {
		return new BouncyCastlePoint(c.createPoint(x, y));
	}

	@Override
	public ECPointWrapper decodePoint(byte[] encodedPoint) {
		return new BouncyCastlePoint(c.decodePoint(encodedPoint));
	}

	@Override
	public BigInteger getA() {
		return c.getA().toBigInteger();
	}

	@Override
	public BigInteger getB() {
		return c.getB().toBigInteger();
	}

	@Override
	public BigInteger getCofactor() {
		return c.getCofactor();
	}

	@Override
	public int getCoordinateSystem() {
		return c.getCoordinateSystem();
	}

	@Override
	public ECPointWrapper getInfinity() {
		
		return new BouncyCastlePoint(c.getInfinity());
	}

	@Override
	public BigInteger getOrder() {
		return c.getOrder();
	}

	@Override
	public ECPointWrapper validatePoint(BigInteger x, BigInteger y) {
		return new BouncyCastlePoint(c.validatePoint(x, y));
	}
	
	@Override
	public String toString() {
		return c.toString();
	}
	@Override
	public ECPointWrapper importPoint(ECPointWrapper point) {
		Object temp = point.getPoint();
		if(temp instanceof ECPoint) {
			return new BouncyCastlePoint(c.importPoint((ECPoint) temp));
		} else {
			throw new InputMismatchException("p and point are not the same type of point:  p is " + point.getClass() + " and point is " + temp.getClass());
		}
	}

	@Override
	public Object getCurve() {
		return c;
	}
	@Override
	public boolean equals(ECCurveWrapper other) {
		if(this == other) return true;
		Object otherC = other.getCurve();
		if(otherC instanceof ECCurve) {
			if(otherC.equals(c)) {
				return true;
			}
		}
		return false;
	}
}
