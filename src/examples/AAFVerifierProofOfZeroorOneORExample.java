package examples;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.Date;
import java.util.Base64.Decoder;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import curve_wrapper.BouncyCastlePoint;
import curve_wrapper.ECCurveWrapper;
import curve_wrapper.ECPointWrapper;
import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.DLPedersenCommitment;
import zero_knowledge_proofs.DLSchnorrProver;
import zero_knowledge_proofs.ECEqualDiscreteLogsProver;
import zero_knowledge_proofs.ECPedersenCommitment;
import zero_knowledge_proofs.ECSchnorrProver;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.ZeroKnowledgeAndProver;
import zero_knowledge_proofs.ZeroKnowledgeOrProver;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class AAFVerifierProofOfZeroorOneORExample {
	public static void main(String[] args) throws IOException, ClassNotFoundException, MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		System.setProperty("javax.net.ssl.trustStore", "resources/Client_Truststore");
		System.setProperty("javax.net.ssl.keyStore", "resources/Server_Keystore");
		System.setProperty("javax.net.ssl.trustStorePassword", "test123");
		System.setProperty("javax.net.ssl.keyStorePassword", "test123");
		System.setProperty("java.security.policy", "resources/mysecurity.policy");
		ServerSocketFactory ssf = ServerSocketFactory.getDefault();
		SocketFactory sf = SocketFactory.getDefault();
		Decoder decoder = Base64.getDecoder();
		
		System.out.println(new Date());
		

		if(args.length != 2) {
			System.out.println("No args, defaulting to [127.0.0.1, 5001]");
			args = new String[2];
			args[0] = "127.0.0.1";
			args[1] = "5001";
		}
		
		
		ServerSocket host = null;
		Socket s;
		ObjectInputStream in;
		ObjectOutputStream out;
		try {
			SocketAddress dest = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
			s = sf.createSocket();
			s.connect(dest);
			System.out.println("Connection to Server successful");
			in = new ObjectInputStream(s.getInputStream());
			out = new ObjectOutputStream(s.getOutputStream());
		}
		catch(Exception e){
			System.out.println("Connection not open, opening server");
			try {
				host = ssf.createServerSocket(Integer.parseInt(args[1]));
				s = host.accept();
				if(args[0].equals(s.getInetAddress().getHostAddress())){
					System.out.println("");
				}
				System.out.println("Connection established");
				out = new ObjectOutputStream(s.getOutputStream());
				in = new ObjectInputStream(s.getInputStream());
			}
			
			catch( java.net.BindException ex)
			{
				SocketAddress dest = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
				s = sf.createSocket();
				s.connect(dest);
				System.out.println("Connection to Server successful");
				in = new ObjectInputStream(s.getInputStream());
				out = new ObjectOutputStream(s.getOutputStream());
			}
		}

		ECPointWrapper g = new BouncyCastlePoint(ECNamedCurveTable.getParameterSpec("secp256k1").getG());
		ECCurveWrapper c = g.getCurve();	
		BigInteger order = c.getOrder();
		ECPointWrapper h = c.decodePoint((byte[]) in.readObject());
		ECPointWrapper y1 = c.decodePoint((byte[]) in.readObject());
		ECPointWrapper y2 = c.decodePoint((byte[]) in.readObject());
		
		ECPointWrapper[] ciphertext = new ECPointWrapper[2];
		ciphertext[0] = c.decodePoint((byte[]) in.readObject());
		ciphertext[1] = c.decodePoint((byte[]) in.readObject());
		
		SecureRandom rand = new SecureRandom();

		ZKPProtocol proof;
		{
			ZKPProtocol innerProof = new ECEqualDiscreteLogsProver();
			ZKPProtocol[] inner = new ZKPProtocol[] {innerProof, innerProof};
			
			proof = new ZeroKnowledgeOrProver(inner, order);
			System.nanoTime();
		}
		
		
		
		/*
		 * Two main things needed for the proof.
		 *   1.  Public inputs  -- Prover and Verifier
		 *   2.  Environment    -- Prover and Verifier
		 */
		
		//Create Public Inputs
		CryptoData publicInputs;
		{
			CryptoData[] inner1 =  new CryptoData[] {new ECPointData(ciphertext[1]), new ECPointData(ciphertext[0])}; 
			CryptoData[] inner2 = new CryptoData[] {new ECPointData(ciphertext[1]), new ECPointData(ciphertext[0].subtract(g))}; 
			publicInputs = new CryptoDataArray(new CryptoDataArray[] {new CryptoDataArray(inner1), new CryptoDataArray(inner2)});
		}
		
		
		CryptoData env;	
		{
			CryptoData[] inner = new CryptoData[] {new ECCurveData(c, g), new ECPointData(y1)};
			
			env = new CryptoDataArray(new CryptoDataArray[] {new CryptoDataArray(inner), new CryptoDataArray(inner)});
		}
		
		CryptoData commEnv;
		{
			CryptoData[] inner = new CryptoData[] {new ECCurveData(c, g), new ECPointData(h)};
			commEnv = new CryptoDataArray(inner);
		}
		
		BigInteger[] challenge = new BigInteger[] {ZKToolkit.random(order, rand), ZKToolkit.random(order, rand)};
		ECPedersenCommitment cCom = new ECPedersenCommitment(challenge[0], challenge[1], commEnv);
		if(proof.maliciousVerify(publicInputs, cCom, challenge, env, in, out, null)) {
			System.out.println("Horray!");
		} else {
			System.out.println("LIAR!");
		}
		
		CryptoData[] transcript = (CryptoData[]) in.readObject();
		
		if(proof.verifyFiatShamir(publicInputs, transcript[0], transcript[1], env)) {
			System.out.println("Horray 2!");
		} else {
			System.out.println("LIAR 2");
		}
	}
}
