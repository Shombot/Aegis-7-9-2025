package curve_wrapper;

import java.io.Serializable;
import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;
/**
 * This class is a wrapper for ECPoint, designed to share most of the functionality of a BouncyCastle ECPoint, specifically the functions I use in my projects
 */
public interface ECPointWrapper {

	ECPointWrapper add(ECPointWrapper toAdd);
	ECPointWrapper subtract(ECPointWrapper toSubtract);
	ECPointWrapper multiply(BigInteger toMultiply);
	ECPointWrapper threeTimes();
	ECPointWrapper twice();
	ECPointWrapper twicePlus(ECPointWrapper toAdd);
	
	boolean equals(ECPointWrapper toCompare);
	ECCurveWrapper getCurve();
	byte[] getEncoded(boolean compressed);
	ECPointWrapper normalize();
	ECPointWrapper negate();
	BigInteger getXCoord();
	BigInteger getYCoord();
	BigInteger getZCoord(int arg);
	BigInteger[] getZCoords();
	BigInteger getAffineXCoord();
	BigInteger getAffineYCoord();
	BigInteger getRawXCoord();
	BigInteger getRawYCoord();
	boolean isInfinity();
	boolean isNormalized();
	boolean isValid();
	
	Object getPoint();
}
