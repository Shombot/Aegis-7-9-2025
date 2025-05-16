package zero_knowledge_proofs;

import java.math.BigInteger;

import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class DLEqualDiscreteLogsRSAProver extends ZKPProtocol {


	//input format:  [y1, y2], [rx, x, orderN], [n, g1, g2]

	@Override
	public CryptoData initialComm(CryptoData input, CryptoData environment) {
		BigInteger[] data = new BigInteger[1];
		CryptoData[] e = null;
		CryptoData[] i = null;
		BigInteger p = null;
		BigInteger g = null;
		BigInteger r = null;
		try {
			e = environment.getCryptoDataArray();
			i = input.getCryptoDataArray();
			p = e[0].getBigInt();
			g = e[1].getBigInt();
			r = i[1].getBigInt();
			data[0] = g.modPow(r, p);
		} catch(NullPointerException exception) {
			if(e == null) {
				throw new NullPointerException("Error in Schnorr Environment Array -- Not an array -- Should be [p, g]\n" + exception.getMessage());
			}
			if(i == null) {
				throw new NullPointerException("Error in Schnorr Inputs Array -- Not an array -- Should be [y, r, x]\n" + exception.getMessage());
			}
			if(e[0] == null) {
				throw new NullPointerException("Error in Schnorr Environment 0 -- Entry is null (should be a prime p)\n" + exception.getMessage());
			}
			if(p == null) {
				throw new NullPointerException("Error in Schnorr Environment 0 -- Not a BigInteger (should be a prime p)\n" + exception.getMessage());
			}
			if(e[1] == null) {
				throw new NullPointerException("Error in Schnorr Environment 1 -- Entry is null (should be a generator)\n" + exception.getMessage());
			}
			if(g == null) {
				throw new NullPointerException("Error in Schnorr Environment 1 -- Not a BigInteger (should be a generator)\n" + exception.getMessage());
			}
			if(i[1] == null) {
				throw new NullPointerException("Error in Schnorr Inputs 1 -- Entry is null (should be a random number r)\n" + exception.getMessage());
			}
			if(r == null) {
				throw new NullPointerException("Error in Schnorr Inputs 1 -- Not a BigInteger (should be a random number r)\n" + exception.getMessage());
			}		
			throw new NullPointerException("Error in unhandled Schnorr null case\n" + exception.getMessage());
		}catch(ArrayIndexOutOfBoundsException exception) {
			if(e.length < 2) {
				throw new ArrayIndexOutOfBoundsException("Error in Environment size -- e.length = " + e.length + " (should be at least 1)\n" + exception.getMessage());
			}
			if(i.length < 3) {
				throw new ArrayIndexOutOfBoundsException("Error in Inputs size -- i.length = " + i.length + " (should be 3)\n" + exception.getMessage());
			}
			throw new ArrayIndexOutOfBoundsException("Error in unhandled Schnorr array case\n" + exception.getMessage());
		}

		CryptoData toReturn = new CryptoDataArray(data);
		return toReturn;
	}

	@Override
	public CryptoData initialCommSim(CryptoData input, BigInteger challenge, CryptoData environment) {
		BigInteger[] data = new BigInteger[1];
		CryptoData[] e = null;		//(y, z) 
		CryptoData[] i = null;
		BigInteger y = null; 
		BigInteger z = null;
		BigInteger g = null;
		BigInteger p = null;
		try {
			e = environment.getCryptoDataArray();
			i = input.getCryptoDataArray();
			y = i[0].getBigInt();
			z = i[1].getBigInt();
			g = e[1].getBigInt();
			p = e[0].getBigInt();
			data[0] = g.modPow(z, p).multiply(y.modPow(challenge.negate(), p)).mod(p);
		}
		catch(NullPointerException exception) {
			if(e == null) {
				throw new NullPointerException("Error in Schnorr Environment Array -- Not an array -- Should be [y,g]\n" + exception.getMessage());
			}
			if(i == null) {
				throw new NullPointerException("Error in Schnorr Inputs Array -- Not an array -- Should be [y, z]\n" + exception.getMessage());
			}
			if(i[0] == null) {
				throw new NullPointerException("Error in Schnorr inputs 0 -- Entry is null (should be a public key y)\n" + exception.getMessage());
			}
			if(y == null) {
				throw new NullPointerException("Error in Schnorr Inputs 0 -- Not a BigInteger (should be a public key y)\n" + exception.getMessage());
			}		
			if(i[1] == null) {
				throw new NullPointerException("Error in Schnorr inputs 1 -- Entry is null (should be a random number z)\n" + exception.getMessage());
			}
			if(z == null) {
				throw new NullPointerException("Error in Schnorr Inputs 1 -- Not a BigInteger (should be a random number z)\n" + exception.getMessage());
			}		
			if(e[1] == null) {
				throw new NullPointerException("Error in Schnorr Environment 1 -- Entry is null (should be a generator)\n" + exception.getMessage());
			}
			if(g == null) {
				throw new NullPointerException("Error in Schnorr Environment 1 -- Not a BigInteger (should be a generator)\n" + exception.getMessage());
			}
			if(e[0] == null) {
				throw new NullPointerException("Error in Schnorr Environment 0 -- Entry is null (should be a prime p)\n" + exception.getMessage());
			}
			if(p == null) {
				throw new NullPointerException("Error in Schnorr Environment 0 -- Not a BigInteger (should be a prime p)\n" + exception.getMessage());
			}
			throw new NullPointerException("Error in unhandled Schnorr case\n" + exception.getMessage());
		}catch(ArrayIndexOutOfBoundsException exception) {
			if(e.length < 2) {
				throw new ArrayIndexOutOfBoundsException("Error in Environment size -- e.length = " + e.length + " (should be at least 1)\n" + exception.getMessage());
			}
			if(i.length < 2) {
				throw new ArrayIndexOutOfBoundsException("Error in Environment size -- i.length = " + i.length + " (should be 2)\n" + exception.getMessage());
			}
			throw new ArrayIndexOutOfBoundsException("Error in unhandled Schnorr array case\n" + exception.getMessage());
		}
		//a = g^z * y^(-c)


		CryptoData toReturn = new CryptoDataArray(data);
		return toReturn;
	}

	@Override
	public CryptoData calcResponse(CryptoData input, BigInteger challenge, CryptoData environment) {
		BigInteger[] array = new BigInteger[1];
		CryptoData[] i = null;
		CryptoData[] e = null;

		BigInteger p = null;
		BigInteger x = null;
		BigInteger r = null;

		try {
			e = environment.getCryptoDataArray();
			i = input.getCryptoDataArray();

			p = e[0].getBigInt();
			x = i[2].getBigInt();
			r = i[1].getBigInt();

			array[0] = (r.add(x.multiply(challenge))).mod(p.subtract(BigInteger.ONE));
		}catch(NullPointerException exception) {
			if(e == null) {
				throw new NullPointerException("Error in Schnorr Environment Array -- Not an array -- Should be [p, g]\n" + exception.getMessage());
			}
			if(i == null) {
				throw new NullPointerException("Error in Schnorr Inputs Array -- Not an array -- Should be [y, r, x]\n" + exception.getMessage());
			}
			if(e[0] == null) {
				throw new NullPointerException("Error in Schnorr Environments 0 -- Entry is null (should be a prime p)\n" + exception.getMessage());
			}
			if(p == null) {
				throw new NullPointerException("Error in Schnorr Environment 0 -- Not a BigInteger (should be a prime p)\n" + exception.getMessage());
			}
			if(i[2] == null) {
				throw new NullPointerException("Error in Schnorr inputs 2 -- Entry is null (should be a private key x)\n" + exception.getMessage());
			}
			if(x == null) {
				throw new NullPointerException("Error in Schnorr Inputs 2 -- Not a BigInteger (should be the private key x)\n" + exception.getMessage());
			}
			if(i[1] == null) {
				throw new NullPointerException("Error in Schnorr inputs 2 -- Entry is null (should be a random number r)\n" + exception.getMessage());
			}
			if(r == null) {
				throw new NullPointerException("Error in Schnorr Inputs 1 -- Not a BigInteger (should be a random number r)\n" + exception.getMessage());
			}	
			throw new NullPointerException("Error in unhandled Schnorr case\n" + exception.getMessage());
		}catch(ArrayIndexOutOfBoundsException exception) {
			if(e.length < 2) {
				throw new ArrayIndexOutOfBoundsException("Error in Environment size -- e.length = " + e.length + " (should be at least 1)\n" + exception.getMessage());
			}
			if(i.length < 3) {
				throw new ArrayIndexOutOfBoundsException("Error in Environment size -- i.length = " + i.length + " (should be 3)\n" + exception.getMessage());
			}
			throw new ArrayIndexOutOfBoundsException("Error in unhandled Schnorr array case\n" + exception.getMessage());
		}
		//System.out.printf("P:\t%s ?= %s\n", ((i[1].modPow(challenge, e[1]).multiply(e[0].modPow(i[2], e[1]))).mod(e[1])), e[0].modPow(array[0], e[1]));

		//System.out.printf("P:\tg = %s\nP:\th = %s\nP:\tp = %s\nP:\tr = %s\nP:\tx = %s\nP:\ty = %s\nP:\tz = %s\nP:\tc = %s\n",e[0],e[1],e[1],i[2],i[0],i[1], array[0], challenge);
		CryptoData toReturn = new CryptoDataArray(array);
		return toReturn;
	}

	@Override
	public CryptoData simulatorGetResponse(CryptoData input) {
		CryptoData[] in = null;
		BigInteger[] out = new BigInteger[1];
		try {
			in = input.getCryptoDataArray();
			out[0] = in[1].getBigInt();
		}
		catch(NullPointerException exception) {
			if(in == null) {
				throw new NullPointerException("Error in Schnorr Inputs Array -- Not an array -- Should be [y, r, x]\n" + exception.getMessage());
			}
			if(in[1] == null) {
				throw new NullPointerException("Error in Schnorr Inputs 1 -- Entry is null (should be a random number z)\n" + exception.getMessage());
			}
			if(out[0] == null) {
				throw new NullPointerException("Error in Schnorr Inputs 1 -- Not a BigInteger (should be a random number z)\n" + exception.getMessage());
			}
			throw new NullPointerException("Error in unhandled Schnorr case\n" + exception.getMessage());
		}catch(ArrayIndexOutOfBoundsException exception) {
			if(in.length < 2) {
				throw new ArrayIndexOutOfBoundsException("Error in Environment size -- i.length = " + in.length + " (should be at least 2)\n" + exception.getMessage());
			}
			throw new ArrayIndexOutOfBoundsException("Error in unhandled Schnorr array case\n" + exception.getMessage());
		}
		return new CryptoDataArray(out);
	}


	@Override
	public CryptoData simulatorGetResponse(CryptoData publicInput, CryptoData secrets) {
		CryptoData[] in = null;
		BigInteger[] out = new BigInteger[1];
		try {
			in = secrets.getCryptoDataArray();
			out[0] = in[0].getBigInt();
		}
		catch(NullPointerException exception) {
			if(in == null) {
				throw new NullPointerException("Error in Schnorr Inputs Array -- Not an array -- Should be [y, z]\n" + exception.getMessage());
			}
			if(in[0] == null) {
				throw new NullPointerException("Error in Schnorr Private Inputs 0 -- Entry is null (should be a random number z)\n" + exception.getMessage());
			}
			if(out[0] == null) {
				throw new NullPointerException("Error in Schnorr Private Inputs 0 -- Not a BigInteger (should be a random number z)\n" + exception.getMessage());
			}
			throw new NullPointerException("Error in unhandled Schnorr case\n" + exception.getMessage());
		}catch(ArrayIndexOutOfBoundsException exception) {
			if(in.length < 2) {
				throw new ArrayIndexOutOfBoundsException("Error in Environment size -- i.length = " + in.length + " (should be at least 2)\n" + exception.getMessage());
			}
			throw new ArrayIndexOutOfBoundsException("Error in unhandled Schnorr array case\n" + exception.getMessage());
		}
		return new CryptoDataArray(out);
	}
	//input format:  [y1, y2]

	@Override
	public boolean verifyResponse(CryptoData input, CryptoData initial_comm, CryptoData response, BigInteger challenge,
			CryptoData environment) {
		
		CryptoData[] e = null;
		CryptoData[] resp = null;
		CryptoData[] i = null;
		CryptoData[] a_pack = null;

		BigInteger y1 = null;
		BigInteger y2 = null;
		BigInteger n = null;
		BigInteger g1 = null;
		BigInteger g2 = null;
		BigInteger z = null;
		BigInteger a1 = null;
		BigInteger a2 = null;
		try {
			e = environment.getCryptoDataArray();
			resp = response.getCryptoDataArray();
			i = input.getCryptoDataArray();
			a_pack = initial_comm.getCryptoDataArray();
			
			y1 = i[0].getBigInt();
			y2 = i[1].getBigInt();
			n = e[0].getBigInt();
			g1 = e[1].getBigInt();
			g2 = e[2].getBigInt();
			z = resp[0].getBigInt();
			a1 = a_pack[0].getBigInt();
			a2 = a_pack[1].getBigInt();
		}catch(NullPointerException exception) {
//			if(e == null) {
//				throw new NullPointerException("Error in Schnorr Environment Array -- Not an array -- Should be [p, g]\n" + exception.getMessage());
//			}
//			if(resp == null) {
//				throw new NullPointerException("Error in Schnorr Response Array -- Not an array -- Should be [z]\n" + exception.getMessage());
//			}
//			if(i == null) {
//				throw new NullPointerException("Error in Schnorr Inputs Array -- Not an array -- Should be [y]\n" + exception.getMessage());
//			}
//			if(a_pack == null) {
//				throw new NullPointerException("Error in Schnorr Initial Comm Array -- Not an array -- Should be [a]\n" + exception.getMessage());
//			}
//			if(i[0] == null) {
//				throw new NullPointerException("Error in Schnorr Inputs 0 -- Entry is null (should be a public key y)\n" + exception.getMessage());
//			}
//			if(y == null) {
//				throw new NullPointerException("Error in Schnorr Inputs 0 -- Not a BigInteger (should be the public key y)\n" + exception.getMessage());
//			}
//			if(e[0] == null) {
//				throw new NullPointerException("Error in Schnorr Environment 0 -- Entry is null (should be a prime p)\n" + exception.getMessage());
//			}
//			if(p == null) {
//				throw new NullPointerException("Error in Schnorr Environment 0 -- Not a BigInteger (should be a prime p)\n" + exception.getMessage());
//			}
//			if(e[1] == null) {
//				throw new NullPointerException("Error in Schnorr Environment 1 -- Entry is null (should be a generator g)\n" + exception.getMessage());
//			}
//			if(g == null) {
//				throw new NullPointerException("Error in Schnorr Environment 1 -- Not a BigInteger (should be a generator g)\n" + exception.getMessage());
//			}
//			if(resp[0] == null) {
//				throw new NullPointerException("Error in Schnorr Response 0 -- Entry is null (should be a random number z)\n" + exception.getMessage());
//			}
//			if(z == null) {
//				throw new NullPointerException("Error in Schnorr Response 0 -- Not a BigInteger (should be a random number z)\n" + exception.getMessage());
//			}
//			if(a_pack[0] == null) {
//				throw new NullPointerException("Error in Schnorr Initial Comm 0 -- Entry is null (should be an initial communication a)\n" + exception.getMessage());
//			}
//			if(a == null) {
//				throw new NullPointerException("Error in Schnorr Initial Comm 0 -- Not a BigInteger (should be an initial communication a)\n" + exception.getMessage());
//			}	
			throw new NullPointerException("Error in unhandled Schnorr case\n" + exception.getMessage());
		}catch(ArrayIndexOutOfBoundsException exception) {
			if(e.length < 2) {
				throw new ArrayIndexOutOfBoundsException("Error in Environment size -- e.length = " + e.length + " (should be at least 2)\n" + exception.getMessage());
			}
			if(i.length < 1) {
				throw new ArrayIndexOutOfBoundsException("Error in Inputs size -- i.length = " + i.length + " (should be 1)\n" + exception.getMessage());
			}
			if(resp.length < 1) {
				throw new ArrayIndexOutOfBoundsException("Error in Response size -- resp.length = " + resp.length + " (should be 1)\n" + exception.getMessage());
			}
			if(a_pack.length < 1) {
				throw new ArrayIndexOutOfBoundsException("Error in InitialComm size -- a_pack.length = " + a_pack.length + " (should be 1)\n" + exception.getMessage());
			}
			throw new ArrayIndexOutOfBoundsException("Error in unhandled Schnorr array case\n" + exception.getMessage());
		}
		
				
		//	return (a * y^c) mod p == (g^z) mod p 
		//System.out.printf("V:\t%s ?= %s\n", (i[0].modPow(challenge, e[1]).multiply(a[0])).mod(e[1]), e[0].modPow(z[0], e[1]));
		return (((y1.modPow(challenge, n).multiply(a1)).mod(n)).equals(g1.modPow(z, n))) && (y2.modPow(challenge, n).multiply(a2).mod(n).equals(g2.modPow(z, n)));
	}

	@Override
	public CryptoData initialComm(CryptoData publicInput, CryptoData secrets, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		
		BigInteger[] data = new BigInteger[2];
		CryptoData[] e = null;
		CryptoData[] i = null;
		BigInteger n = null;
		BigInteger g1 = null;
		BigInteger g2 = null;
		BigInteger r = null;
		
		try {
			e = environment.getCryptoDataArray();
			i = secrets.getCryptoDataArray();
			
			n = e[0].getBigInt();
			g1 = e[1].getBigInt();
			g2 = e[2].getBigInt();
			r = i[0].getBigInt();
			
		}catch(NullPointerException exception) {
//			if(e == null) {
//				throw new NullPointerException("Error in Schnorr Environment Array -- Not an array\n" + exception.getMessage());
//			}
//			if(i == null) {
//				throw new NullPointerException("Error in Schnorr Private Inputs Array -- Not an array\n" + exception.getMessage());
//			}
//			if(e[0] == null) {
//				throw new NullPointerException("Error in Schnorr Environment 0 -- Entry is null (should be a prime p)\n" + exception.getMessage());
//			}
//			if(n == null) {
//				throw new NullPointerException("Error in Schnorr Environment 0 -- Not a BigInteger (should be a prime p)\n" + exception.getMessage());
//			}
//			if(e[1] == null) {
//				throw new NullPointerException("Error in Schnorr Environment 1 -- Entry is null (should be a generator)\n" + exception.getMessage());
//			}
//			if(g1 == null) {
//				throw new NullPointerException("Error in Schnorr Environment 1 -- Not a BigInteger (should be a generator)\n" + exception.getMessage());
//			}
//			if(i[0] == null) {
//				throw new NullPointerException("Error in Schnorr Private Inputs 0 -- Entry is null (should be a random number r)\n" + exception.getMessage());
//			}
//			if(r == null) {
//				throw new NullPointerException("Error in Schnorr Private Inputs 0 -- Not a BigInteger (should be a random number r)\n" + exception.getMessage());
//			}		
			throw new NullPointerException("Error in unhandled Schnorr null case\n" + exception.getMessage());
		}catch(ArrayIndexOutOfBoundsException exception) {
			if(e.length < 2) {
				throw new ArrayIndexOutOfBoundsException("Error in Environment size -- e.length = " + e.length + " (should be at least 2)\n" + exception.getMessage());
			}
			if(i.length < 2) {
				throw new ArrayIndexOutOfBoundsException("Error in Private Inputs size -- i.length = " + i.length + " (should be 2)\n" + exception.getMessage());
			}
			throw new ArrayIndexOutOfBoundsException("Error in unhandled Schnorr array case\n" + exception.getMessage());
		}
		data[0] = g1.modPow(r, n);
		data[1] = g2.modPow(r, n);

		
		
		CryptoData toReturn = new CryptoDataArray(data);
		return toReturn;
	}
	@Override
	public CryptoData initialCommSim(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment)
					throws MultipleTrueProofException, ArraySizesDoNotMatchException, NoTrueProofException {

		BigInteger[] data = new BigInteger[1];
		CryptoData[] pI = publicInput.getCryptoDataArray();
		CryptoData[] s = secrets.getCryptoDataArray();
		CryptoData[] e = environment.getCryptoDataArray();		//(y, z) 
		BigInteger y1 = pI[0].getBigInt();
		BigInteger y2 = pI[1].getBigInt();
		BigInteger z = s[0].getBigInt();
		BigInteger g1 = e[1].getBigInt();
		BigInteger g2 = e[2].getBigInt();
		BigInteger n = e[0].getBigInt();
		//a = g^z * y^(-c)
		data[0] = g1.modPow(z, n).multiply(y1.modPow(challenge.negate(), n)).mod(n);
		data[0] = g2.modPow(z, n).multiply(y2.modPow(challenge.negate(), n)).mod(n);


		CryptoData toReturn = new CryptoDataArray(data);
		return toReturn;
	}

	@Override
	public CryptoData calcResponse(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment) throws NoTrueProofException, MultipleTrueProofException {
		BigInteger[] array = new BigInteger[1];

		CryptoData[] s = secrets.getCryptoDataArray();
		BigInteger x = s[1].getBigInt();
		BigInteger orderN = s[2].getBigInt();
		BigInteger r = s[0].getBigInt();

		array[0] = (r.add(x.multiply(challenge))).mod(orderN);
		//System.out.printf("P:\t%s ?= %s\n", ((i[1].modPow(challenge, e[1]).multiply(e[0].modPow(i[2], e[1]))).mod(e[1])), e[0].modPow(array[0], e[1]));

		//System.out.printf("P:\tg = %s\nP:\th = %s\nP:\tp = %s\nP:\tr = %s\nP:\tx = %s\nP:\ty = %s\nP:\tz = %s\nP:\tc = %s\n",e[0],e[1],e[1],i[2],i[0],i[1], array[0], challenge);
		CryptoData toReturn = new CryptoDataArray(array);
		return toReturn;
	}

}
