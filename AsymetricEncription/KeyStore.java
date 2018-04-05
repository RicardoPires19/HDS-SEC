package AsymetricEncription;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class KeyStore {
	
	public static void main(String[] args) throws Exception{
		 KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		 kpg.initialize(2048);

		 KeyPair kp = kpg.genKeyPair();

		 KeyFactory fact = KeyFactory.getInstance("RSA");

		 RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(),
		        RSAPublicKeySpec.class);
		 saveToFile("keystore.jks", 
		        pub.getModulus(), pub.getPublicExponent());

		 System.out.println(pub.toString());
		 
		 RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(),
		        RSAPrivateKeySpec.class);
		 saveToFile("keystore.jks", 
		         priv.getModulus(), priv.getPrivateExponent());
		 
		 System.out.println(readPublicKey().toString());

	}
	
	
	private static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws Exception {
		ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
		try {
			oout.writeObject(mod);
			oout.writeObject(exp);
		} catch (Exception e) {
			throw new Exception(e);
		} finally {
			oout.close();
		}
	}
	private static PublicKey readPublicKey() throws Exception {
	    InputStream in = new FileInputStream("keystore.jks");
	    ObjectInputStream oin =
	            new ObjectInputStream(new BufferedInputStream(in));
	    try {
	        BigInteger m = (BigInteger) oin.readObject();
	        BigInteger e = (BigInteger) oin.readObject();
	        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
	        KeyFactory fact = KeyFactory.getInstance("RSA");
	        PublicKey pubKey = fact.generatePublic(keySpec);
	        return pubKey;
	    } catch (Exception e) {
	        throw new Exception(e);
	    } finally {
	        oin.close();
	    }
	}
}
