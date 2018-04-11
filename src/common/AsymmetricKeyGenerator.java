package common;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class AsymmetricKeyGenerator {
	private KeyPairGenerator keyGen;
	private KeyPair pair;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private String keyName;

	public String getKeyName() {
		return keyName;
	}

	public void setKeyName(String keyName) {
		this.keyName = keyName;
	}

	public AsymmetricKeyGenerator(int keylength, String keyName) throws NoSuchAlgorithmException, NoSuchProviderException {
		this.keyGen = KeyPairGenerator.getInstance("RSA");
		this.keyGen.initialize(keylength);
		this.keyName = keyName;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	
	public PublicKey getPublicKey() {
		return publicKey;
	}
	
	public void createKeyPair() {
		this.pair = this.keyGen.generateKeyPair();
		this.privateKey = pair.getPrivate();
		this.publicKey = pair.getPublic();
	}

	private void writeToFile(String path, byte[] key) throws IOException {
		File f = new File(path);
		f.getParentFile().mkdirs();

		FileOutputStream fos = new FileOutputStream(f);
		fos.write(key);
		fos.flush();
		fos.close();
	}
	
	public void WritePublicKey(String path) {
		try {
			writeToFile(path, publicKey.getEncoded());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void WriteKeys() {
		try {
			writeToFile("KeyPair/"+ keyName + "publicKey", publicKey.getEncoded());
			writeToFile("KeyPair/"+ keyName + "privateKey", privateKey.getEncoded());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}
