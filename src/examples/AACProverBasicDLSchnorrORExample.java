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

import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.DLSchnorrProver;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.ZeroKnowledgeAndProver;
import zero_knowledge_proofs.ZeroKnowledgeOrProver;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class AACProverBasicDLSchnorrORExample {
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
		
		BigInteger p = new BigInteger("24880416976081453327269227415025938813219052085951345990705113268399560622403139595170216299210138771196484641733215886116725311718776421856732044338312259323822601223552732252647990694969821147034294500419912890477882931884396903888000463538905383304259801328910235181823051905905676739380166192113721547291207530241882010613367414068559043276569349187531228603838471412389267496765655075049933405554759096262547024500301321714755576808234887361152037293045288037601508143626276382971596423451229153003269013848297885338715969400319507575296464734849452692701646616863295870934354487214478315351871431026811844373163");
		SecureRandom rand = new SecureRandom();
		BigInteger g;
		while(true) {
			g = ZKToolkit.random(p, rand);
			if(g.equals(BigInteger.ZERO)) continue;
			if(g.equals(BigInteger.ONE)) continue;
			if(g.modPow(BigInteger.valueOf(2), p).equals(BigInteger.ONE)) continue;
			if(g.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2)), p).equals(BigInteger.ONE)) continue;
			break;
		}
		BigInteger h;
		while(true) {
			h = ZKToolkit.random(p, rand);
			if(h.equals(BigInteger.ZERO)) continue;
			if(h.equals(BigInteger.ONE)) continue;
			if(h.modPow(BigInteger.valueOf(2), p).equals(BigInteger.ONE)) continue;
			if(h.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2)), p).equals(BigInteger.ONE)) continue;
			break;
		}
		
		out.writeObject(g);
		out.writeObject(h);
		out.flush();
		
		BigInteger x1 = ZKToolkit.random(p, rand);
		BigInteger x2 = ZKToolkit.random(p, rand);
		BigInteger y1 = g.modPow(x1, p);
		BigInteger y2 = g.modPow(x2, p);
		
		out.writeObject(y1);
		out.writeObject(y2);
		out.flush();
		
		ZKPProtocol proof;
		{
			ZKPProtocol innerProof = new DLSchnorrProver();
			ZKPProtocol[] inner = new ZKPProtocol[] {innerProof, innerProof};
			
			proof = new ZeroKnowledgeOrProver(inner, p);
		}
		
		/*
		 * Three main things needed for the proof.
		 *   1.  Public inputs  -- Prover and Verifier
		 *   2.  Secrets        -- Prover
		 *   3.  Environment    -- Prover and Verifier
		 */
		
		//Create Public Inputs
		CryptoData publicInputs;
		{
			CryptoData[] inner1 = new CryptoData[1];
			CryptoData[] inner2 = new CryptoData[1];
			inner1[0] = new BigIntData(y1);
			inner2[0] = new BigIntData(y2);
			publicInputs = new CryptoDataArray(new CryptoDataArray[] {new CryptoDataArray(inner1), new CryptoDataArray(inner2)});
		}
		//Prover will create secrets section

		CryptoData secrets;
		{
			BigInteger r1 = ZKToolkit.random(p, rand);
			BigInteger r2 = ZKToolkit.random(p, rand);
			BigInteger[] inner1 = new BigInteger[] {r1};
			BigInteger[] inner2 = new BigInteger[] {r2, x2};
			BigInteger[] simChal = new BigInteger[] {ZKToolkit.random(p, rand), null};
			secrets = new CryptoDataArray(new CryptoDataArray[] {new CryptoDataArray(inner1), new CryptoDataArray(inner2), new CryptoDataArray(simChal)});
		}
		//Create Environment
		CryptoData env;
		{
			BigInteger[] inner = new BigInteger[] {p, g};
			env = new CryptoDataArray(new CryptoDataArray[] {new CryptoDataArray(inner), new CryptoDataArray(inner)});
		}
		CryptoData commEnv;
		{
			BigInteger[] inner = new BigInteger[] {p, g, h};
			commEnv = new CryptoDataArray(inner);
		}
		proof.trueZKProve(publicInputs, secrets, env, commEnv, in, out);
		
		CryptoData[] transcript = proof.proveFiatShamir(publicInputs, secrets, env);
		
		System.out.println(transcript[0]);
		
		out.writeObject(transcript);
		out.flush();
		
	}
}
