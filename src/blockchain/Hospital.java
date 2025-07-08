package blockchain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import org.bouncycastle.util.encoders.Base64; // For encoding

//Always use the setter for the keys, they automatically update the string as well
public class Hospital {
	public PublicKey pubKey;
	public String pubString;
	private PrivateKey privKey;
	private String privString;
	private String data;
	private String ptrData;
	private String prevDataHP;
	private SecretKey symmetricKey;
	private String symmetricString;
	
	public Hospital(SecretKey symmetricKey, String data, String ptrData, String prevDataHP) throws NoSuchAlgorithmException {
		this(data, ptrData, prevDataHP);
		setSymmetricKey(symmetricKey);
	}
	
	public Hospital(PublicKey pubKey, PrivateKey privKey, SecretKey symmetricKey, String data, String ptrData, String prevDataHP) throws NoSuchAlgorithmException {
		this(data, ptrData, prevDataHP);
		setPubKey(pubKey);
		setPrivKey(privKey);
		setSymmetricKey(symmetricKey);
	}
	
	public Hospital(PublicKey pubKey, PrivateKey privKey, String data, String ptrData, String prevDataHP) throws NoSuchAlgorithmException {
		this(data, ptrData, prevDataHP);
		setPubKey(pubKey);
		setPrivKey(privKey);
	}
	
	public Hospital(String data, String ptrData, String prevDataHP) throws NoSuchAlgorithmException {
		while(privKey == null || pubKey == null || pubString == null || privString == null) {
			genKeys();
		}
		
		//probably redundant since I take care of the strings every time we add a key
		if(symmetricKey != null && symmetricString == null) {
			symmetricString = generateStringFromSymmetricKey(symmetricKey);
		}

		this.data = data;
		this.ptrData = ptrData;
		this.prevDataHP = prevDataHP;
	}
	
	//Only does public and private, not symmetric
	public void genKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

        SecureRandom secureRandom = new SecureRandom();
        keyGen.initialize(2048, secureRandom); // 2048-bit RSA key

        KeyPair keyPair = keyGen.generateKeyPair();

        setPrivKey(keyPair.getPrivate());
        setPubKey(keyPair.getPublic());
        
        // You can then encode and store/use these keys as needed
        System.out.println("Private Key Hospital (Base64): " + privString);
        System.out.println("Public Key Hospital (Base64): " + pubString);
    }
	
	public String generateStringFromSymmetricKey(SecretKey symmetricKey) {
		return new String(Base64.encode(symmetricKey.getEncoded()));
	}
	
	public String generateStringFromPublicKey(PublicKey pubKey) {
		return new String(Base64.encode(pubKey.getEncoded()));
	}
	
	public String generateStringFromPrivateKey(PrivateKey privKey) {
		return new String(Base64.encode(privKey.getEncoded()));
	}
	
	public String getData() {
		return data;
	}
	
	public void setData(String data) {
		this.data = data;
	}
	
	public String getPtrData() {
		return ptrData;
	}
	
	public void setPtrData(String ptrData) {
		this.ptrData = ptrData;
	}
	
	public String getPrevDataHP() {
		return prevDataHP;
	}
	
	public void setPrevDataHP(String prevDataHP) {
		this.prevDataHP = prevDataHP;
	}
	
    public PublicKey getPubKey() {
        return pubKey;
    }

    public void setPubKey(PublicKey pubKey) {
        this.pubKey = pubKey;
        setPubString(generateStringFromPublicKey(pubKey)); //makes sure the string is always updated
    }

    public String getPubString() {
        return pubString;
    }

    public void setPubString(String pubString) {
        this.pubString = pubString;
    }

    public PrivateKey getPrivKey() {
        return privKey;
    }

    public void setPrivKey(PrivateKey privKey) {
        this.privKey = privKey;
        setPrivString(generateStringFromPrivateKey(privKey)); //makes sure the string is always updated
    }

    public String getPrivString() {
        return privString;
    }

    public void setPrivString(String privString) {
        this.privString = privString;
    }
    
    public SecretKey getSymmetricKey() {
        return symmetricKey;
    }

    public void setSymmetricKey(SecretKey symmetricKey) {
        this.symmetricKey = symmetricKey;
        setSymmetricString(generateStringFromSymmetricKey(symmetricKey)); //makes sure the string is always updated
    }
    
    public String getSymmetricString() {
    	return symmetricString;
    }
    
    public void setSymmetricString(String symmetricString) {
    	this.symmetricString = symmetricString;
    }
}
