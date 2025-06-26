package curve_wrapper;

import java.math.BigInteger;
import java.util.InputMismatchException;

import net.i2p.crypto.eddsa.math.GroupElement;

public class Ed25519Point implements ECPointWrapper {

	private static final long serialVersionUID = -7059971861921115029L;
	final private GroupElement point;
	
	public Ed25519Point(GroupElement point) {
		this.point = point;
	}
	@Override
	public Ed25519Point add(ECPointWrapper toAdd) {
		if(toAdd instanceof Ed25519Point) {
			GroupElement temp = ((Ed25519Point) toAdd).getPoint();
			return new Ed25519Point(point.add(temp));
		}
		throw new InputMismatchException("this and toAdd are not the same type");
	}

	@Override
	public Ed25519Point subtract(ECPointWrapper toSubtract) {
		if(toSubtract instanceof Ed25519Point) {
			GroupElement temp = ((Ed25519Point) toSubtract).getPoint();
			return new Ed25519Point(point.sub(temp));
		}
		throw new InputMismatchException("this and toSubtract are not the same type");
	}

	@Override
	public Ed25519Point multiply(BigInteger toMultiply) {
		toMultiply = toMultiply.mod(getCurve().getOrder());
		byte[] mult = new byte[32];
		byte[] temp = toMultiply.toByteArray();
		for(int i = 0; i < temp.length; i++) {
			mult[i] = temp[(temp.length-i)-1];
		}
//		System.out.println(Arrays.toString(mult));
		return new Ed25519Point(point.scalarMultiply(mult));
	}

	@Override
	public Ed25519Point threeTimes() {
		return new Ed25519Point(point.scalarMultiply(new byte[] {3}));
	}

	@Override
	public Ed25519Point twice() {
		return new Ed25519Point(point.dbl());
	}

	@Override
	public Ed25519Point twicePlus(ECPointWrapper toAdd) {
		if(toAdd instanceof Ed25519Point) {
			GroupElement temp = ((Ed25519Point) toAdd).getPoint();
			return new Ed25519Point(point.scalarMultiply(new byte[] {2}).add(temp));
		}
		throw new InputMismatchException("this and toAdd are not the same type");
	}

	@Override
	public boolean equals(ECPointWrapper toCompare) {
		if(toCompare instanceof Ed25519Point) {
			GroupElement temp = ((Ed25519Point) toCompare).getPoint();
			return temp.toP3().equals(point.toP3());
		}
		return false;
	}

	@Override
	public ECCurveWrapper getCurve() {
		// TODO Auto-generated method stub
		return new Ed25519Curve(point.getCurve());
	}

	@Override
	public byte[] getEncoded(boolean compressed) {
		return point.toByteArray();
	}

	@Override
	public Ed25519Point normalize() {
		return this;
	}

	@Override
	public Ed25519Point negate() {
		// TODO Auto-generated method stub
		return new Ed25519Point(point.negate());
	}

	@Override
	public BigInteger getXCoord() {
		// TODO Auto-generated method stub
		return new BigInteger(0, point.getX().toByteArray());
	}

	@Override
	public BigInteger getYCoord() {
		return new BigInteger(0, point.getY().toByteArray());
	}

	@Override
	public BigInteger getZCoord(int arg) {
		return new BigInteger(0, point.getZ().toByteArray());
	}

	@Override
	public BigInteger[] getZCoords() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BigInteger getAffineXCoord() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BigInteger getAffineYCoord() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BigInteger getRawXCoord() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BigInteger getRawYCoord() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isInfinity() {
		// TODO Auto-generated method stub
		return point.equals(point.scalarMultiply(new byte[] {0}));
	}

	@Override
	public boolean isNormalized() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isValid() {
		// TODO Auto-generated method stub
		return point.isOnCurve();
	}

	@Override
	public GroupElement getPoint() {
		return point;
	}
	@Override
	public String toString() {
		return point.toString();
	}
	@Override
	public boolean equals(Object toCompare) {
		System.out.println("Right equals?");
		if(toCompare instanceof Ed25519Point) {
			return point.toP3().equals(((Ed25519Point)toCompare).getPoint().toP3());
		}
		return false;
	}
}
