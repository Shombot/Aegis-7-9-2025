package test2;

import java.math.BigInteger;

public class BigIntegerByteArrayTest{
	 
    public static void main(String[] args)
    {
    	for(int i = 0; i < 50; i++) {
    		System.out.printf("%s,=Average(B%d:B%d),=Average(C%d:C%d)\n", BigInteger.TWO.shiftLeft(i), 493+(10*i), 503+(10*i), 493+(10*i), 503+(10*i));
    	}
    	System.out.println();
    	BigInteger blah = BigInteger.valueOf(453215343);
    	byte[] blahBytes = blah.toByteArray();
    	System.out.println(blahBytes.length);
    	for(int i = 0; i < blahBytes.length; i++) {
    		System.out.println(blahBytes[i]& 0xFF);
    	}

    	System.out.println("bitlength = " + blah.bitLength());
    	System.out.println(blah.bitLength()/8);
    	System.out.println(blahBytes.length);
    	int j = blah.bitLength()%(8*(blahBytes.length-1)) - 1;
    	for(int i = 0; i < blahBytes.length; i++) {
    		System.out.print(" ");
    		for(; j >= 0; j--) {
    			System.out.print((int) ((blahBytes[i] >> j) & 1));	
    		}
    		j = 7;
    	}
    	
    	System.out.println();
    	System.out.println();
    	for(int i = 0; i < blah.bitLength(); i++) {
    		if(blah.testBit((blah.bitLength()-1)-i)) System.out.print(1);
    		else System.out.print(0);
    	}
    }
 
  
 
}