package curve_wrapper;

import java.math.BigInteger;


public interface ECCurveWrapper {
	//ConfigWrapper configure();
	//ECLookupTableWrapper createCacheSafeLookupTable(ECPointWrapper[] arg0, int arg1, int arg2);
	ECPointWrapper createPoint(BigInteger x, BigInteger y);
	ECPointWrapper decodePoint(byte[] encodedPoint);
	BigInteger getA();
	BigInteger getB();
	BigInteger getCofactor();
	int getCoordinateSystem();
	ECPointWrapper getInfinity();
	BigInteger getOrder();
	ECPointWrapper validatePoint(BigInteger x, BigInteger y);
	ECPointWrapper importPoint(ECPointWrapper point);

	Object getCurve();
	boolean equals(ECCurveWrapper other);
}
