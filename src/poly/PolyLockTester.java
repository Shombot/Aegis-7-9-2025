package poly;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Enumeration;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import curve_wrapper.BouncyCastlePoint;
import curve_wrapper.ECCurveWrapper;
import curve_wrapper.ECPointWrapper;
import poly.PolyLock;
import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class PolyLockTester {
	public static void main(String[] args) {
		int numExperiments = 50;
		int upTo = 20;
		boolean bestCase = false ;
		long[][] data = new long[numExperiments][5];
		for(int j = 20; j <= upTo; j++) {
			for(int k = 0; k < numExperiments; k++) {
				try {

					ByteArrayOutputStream streamOut = new ByteArrayOutputStream();
					ObjectOutputStream out = new ObjectOutputStream(streamOut);

					ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

					SecureRandom rand = new SecureRandom();
					ECPointWrapper g = new BouncyCastlePoint(spec.getG());
					ECCurveWrapper c = g.getCurve();
					BigInteger order = c.getOrder();
					ECPointWrapper h = g.multiply(ZKToolkit.random(order, rand));

					int n = j;

					ECCurveWrapper[] curves = new ECCurveWrapper[n];
					ECPointWrapper[][] gens = new ECPointWrapper[n][2];

					curves[0] = c;

					


					gens[0][0] = g;
					gens[0][1] = h;
					if(bestCase) {

						for(int i = 1; i < n; i++) {
							curves[i] = c;
	
							gens[i][0] = g;
							gens[i][1] = h;
						}
					}
					else
					{
						ECNamedCurveParameterSpec spec2 = ECNamedCurveTable.getParameterSpec("curve25519");
						ECPointWrapper g2 = new BouncyCastlePoint(spec2.getG());
						ECPointWrapper h2 = g2.multiply(ZKToolkit.random(spec2.getCurve().getOrder(), rand));
						for(int i = 1; i < n; i++) {
							curves[i] = g2.getCurve();
	
							gens[i][0] = g2;
							gens[i][1] = h2;
						}
					}
					BigInteger[][] keys = new BigInteger[n][1];
					ECPointWrapper[] pubKeys = new ECPointWrapper[n];
					CryptoData[] environments = new CryptoData[n];
					for(int i = 0; i < keys.length; i++) {
						keys[i][0] = ZKToolkit.random(curves[i].getOrder(), rand);
						pubKeys[i] = gens[i][0].multiply(keys[i][0]);
						environments[i] = new CryptoDataArray(new CryptoData[] {new ECCurveData(curves[i], gens[i][0]), new ECPointData(gens[i][1])});
					}

					long startTime = System.nanoTime();
					PolyLock lock = new PolyLock(new CryptoDataArray(pubKeys).getCryptoDataArray(), keys, environments, rand);

					long endTime = System.nanoTime();

					//				System.out.print((endTime-startTime) + ", ");
					data[k][0] = (endTime-startTime);
					startTime = System.nanoTime();
					ZKPProtocol prover = lock.getProver(order);


					CryptoData proverData = lock.buildProverData(environments, order, rand);
					CryptoData publicData = lock.buildPublicInputs(environments);
					CryptoData env = lock.buildEnvironment(environments);

					CryptoData[] outputs = prover.proveFiatShamir(publicData, proverData, env);

					endTime = System.nanoTime();

					out.writeObject(lock);
					out.writeObject(outputs);
					out.flush();
					//				System.out.print((endTime-startTime) + ", ");
					data[k][1] = (endTime-startTime);
					startTime = System.nanoTime();
					ByteArrayInputStream stream = new ByteArrayInputStream(streamOut.toByteArray());

					ObjectInputStream in = new ObjectInputStream(stream);
					lock = (PolyLock) in.readObject();
					outputs = (CryptoData[]) in.readObject();

					publicData = lock.buildPublicInputs(environments);
					env = lock.buildEnvironment(environments);
					prover = lock.getProver(order);
					boolean verify = lock.verifyHiddenValues(new CryptoDataArray(pubKeys).getCryptoDataArray(), environments);
					if(!verify) {
						System.out.println("Not my polynomial!");

					}
					else{
						verify = prover.verifyFiatShamir(publicData, outputs[0], outputs[1], env);
						if(!verify) {
							System.out.println("Bad Proof");
						}
					}
					endTime = System.nanoTime(); 


					//				System.out.print((endTime-startTime) + ", ");
					data[k][2] = (endTime-startTime);

					startTime = System.nanoTime();
					BigInteger[] result = lock.release(1,  keys[1][0], environments);


					endTime = System.nanoTime();

					//				System.out.print((endTime-startTime) + ", \n");
					data[k][3] = (endTime-startTime);

					for(int i = 0; i < result.length; i++) {

						if(!keys[i].equals(result[i])) {
							System.out.println("Problem!");
						}
					} 
					data[k][4] = streamOut.toByteArray().length;
				} catch (IOException | ClassNotFoundException | MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			long[] total = new long[data[0].length];
			for(int k = 0; k < numExperiments; k++) {
				for(int i = 0; i < data[k].length; i++) {
					total[i] += data[k][i];
				}
			}
			for(int i = 0; i < total.length - 1; i++) {
				System.out.print((total[i] * 1.0) / numExperiments / 1000000000 + ", "  );
			}
			System.out.print((total[4] * 1.0) / numExperiments + ", "  );
			System.out.println();
		}
	}
}
