package AsymetricEncription;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class KeyStore {
	
	public KeyStore(){	 
	}
	
	public static void createKeyPair(String user) throws Exception{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		 kpg.initialize(512);

		 KeyPair kp = kpg.genKeyPair();

		 KeyFactory fact = KeyFactory.getInstance("RSA");
		 
		 File storeFolder = new File("KeyStore");
		 storeFolder.mkdir();
		 
		 RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(),
		        RSAPublicKeySpec.class);
		 saveToFile("KeyStore\\publicKey"+user, 
		        pub.getModulus(), pub.getPublicExponent());
		 RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(),
		        RSAPrivateKeySpec.class);
		 saveToFile("KeyStore\\privateKey"+user, 
		         priv.getModulus(), priv.getPrivateExponent());
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
	public static PublicKey readPublicKey(String user) throws Exception {
	    InputStream in = new FileInputStream("KeyStore\\publicKey"+user);
	    ObjectInputStream oin =
	            new ObjectInputStream(new BufferedInputStream(in));
	    try {
	        BigInteger m = (BigInteger) oin.readObject();
	        BigInteger e = (BigInteger) oin.readObject();
	        RSAPrivateKeySpec pkeySpec = new RSAPrivateKeySpec(m,e);
	        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
	        KeyFactory fact = KeyFactory.getInstance("RSA");
	        PublicKey pubKey = fact.generatePublic(keySpec);
	        PrivateKey privKey = fact.generatePrivate(pkeySpec);
	        return pubKey;
	    } catch (Exception e) {
	        throw new Exception(e);
	    } finally {
	        oin.close();
	    }
	}
	
	public static PrivateKey readPrivateKey(String user) throws Exception{
		InputStream in = new FileInputStream("KeyStore\\privateKey"+user);
	    ObjectInputStream oin =
	            new ObjectInputStream(new BufferedInputStream(in));
	    try {
	        BigInteger m = (BigInteger) oin.readObject();
	        BigInteger e = (BigInteger) oin.readObject();
	        RSAPrivateKeySpec pkeySpec = new RSAPrivateKeySpec(m,e);
	        KeyFactory fact = KeyFactory.getInstance("RSA");
	        PrivateKey privKey = fact.generatePrivate(pkeySpec);
	        return privKey;
	    } catch (Exception e) {
	        throw new Exception(e);
	    } finally {
	        oin.close();
	    }
	}
}
