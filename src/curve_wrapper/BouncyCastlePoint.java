package curve_wrapper;

import java.math.BigInteger;
import java.util.InputMismatchException;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class BouncyCastlePoint implements ECPointWrapper {

	final private ECPoint p;
	
	public BouncyCastlePoint(ECPoint p) {
		this.p = p;
	}
	
	@Override
	public ECPointWrapper add(ECPointWrapper toAdd) {
		Object temp = toAdd.getPoint();
		if(temp instanceof ECPoint) {
			return new BouncyCastlePoint(p.add((ECPoint) temp));
		} else {
			throw new InputMismatchException("p and toAdd are not the same type of point:  p is " + p.getClass() + " and toAdd is " + temp.getClass());
		}
	}

	@Override
	public ECPointWrapper subtract(ECPointWrapper toSubtract) {
		Object temp = toSubtract.getPoint();
		if(temp instanceof ECPoint) {
			return new BouncyCastlePoint(p.subtract((ECPoint) temp));
		} else {
			throw new InputMismatchException("p and toSubtract are not the same type of point:  p is " + p.getClass() + " and toSubtract is " + temp.getClass());
		}	
	}

	@Override
	public ECPointWrapper multiply(BigInteger toMultiply) {
		return new BouncyCastlePoint(p.multiply(toMultiply));
	}

	@Override
	public ECPointWrapper threeTimes() {
		return new BouncyCastlePoint(p.threeTimes());
	}

	@Override
	public ECPointWrapper twice() {
		return new BouncyCastlePoint(p.twice());
	}

	@Override
	public ECPointWrapper twicePlus(ECPointWrapper toAdd) {
		Object temp = toAdd.getPoint();
		if(temp instanceof ECPoint) {
			return new BouncyCastlePoint(p.twicePlus((ECPoint) temp));
		} else {
			throw new InputMismatchException("p and toAdd are not the same type of point:  p is " + p.getClass() + " and toAdd is " + temp.getClass());
		}
	}

	@Override
	public boolean equals(ECPointWrapper toCompare) {
		return p.equals(toCompare.getPoint());
	}

	@Override
	public ECCurveWrapper getCurve() {
		return new BouncyCastleCurve(p.getCurve());
	}

	@Override
	public byte[] getEncoded(boolean compressed) {
		return p.getEncoded(compressed);
	}

	@Override
	public ECPointWrapper normalize() {
		return new BouncyCastlePoint(p.normalize());
	}

	@Override
	public ECPointWrapper negate() {
		return new BouncyCastlePoint(p.negate());
	}

	@Override
	public BigInteger getXCoord() {
		return p.getXCoord().toBigInteger();
	}

	@Override
	public BigInteger getYCoord() {
		return p.getYCoord().toBigInteger();
	}

	@Override
	public BigInteger getZCoord(int arg) {
		return p.getZCoord(arg).toBigInteger();
	}

	@Override
	public BigInteger[] getZCoords() {
		ECFieldElement[] temp = p.getZCoords();
		BigInteger[] toReturn = new BigInteger[temp.length];
		for(int i = 0; i < temp.length; i++) {
			toReturn[i] = temp[i].toBigInteger();
		}
		return toReturn;
	}

	@Override
	public BigInteger getAffineXCoord() {
		return p.getAffineXCoord().toBigInteger();
	}

	@Override
	public BigInteger getAffineYCoord() {
		return p.getAffineYCoord().toBigInteger();
	}

	@Override
	public BigInteger getRawXCoord() {
		return p.getRawXCoord().toBigInteger();
	}

	@Override
	public BigInteger getRawYCoord() {
		return p.getRawYCoord().toBigInteger();
	}

	@Override
	public boolean isInfinity() {
		return p.isInfinity();
	}

	@Override
	public boolean isNormalized() {
		// TODO Auto-generated method stub
		return p.isNormalized();
	}

	@Override
	public boolean isValid() {
		// TODO Auto-generated method stub
		return p.isValid();
	}

	@Override
	public ECPoint getPoint() {
		return p;
	}
	@Override
	public String toString() {
		return p.toString() + " (" + p.getClass() + ")";
	}

}
