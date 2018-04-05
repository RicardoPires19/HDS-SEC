package AsymetricEncription;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class AsymmetricCryptography {
	private String path;
	private String hash;
	private byte[] encHash;
	private Cipher cipher;
	
	public AsymmetricCryptography(String path) throws NoSuchAlgorithmException, NoSuchPaddingException {
		this.cipher = Cipher.getInstance("RSA");
		this.path = path;
	}
	
	public AsymmetricCryptography() throws NoSuchAlgorithmException, NoSuchPaddingException{
		this.cipher = Cipher.getInstance("RSA");
	}
	
	private void createHash() throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		try (InputStream is = Files.newInputStream(Paths.get(path));
		     DigestInputStream dis = new DigestInputStream(is, md)) 
		{
		} catch (IOException e) {
			e.printStackTrace();
		}
		byte[] digest = md.digest();
		
		hash = new String(digest, "UTF-8");
	}
	
	public byte[] createHash(String args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		    MessageDigest md = MessageDigest.getInstance("MD5");
		    md.update(args.getBytes());
		    return md.digest();
	}
	
	public byte[] Encrypt(Key key, String obj){
		try {
			this.cipher.init(Cipher.ENCRYPT_MODE, key);
			encHash = cipher.doFinal(obj.getBytes());
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		}
		return  encHash;
	}
	
	public String Decrypt(Key key, byte[] obj){
		try {
			this.cipher.init(Cipher.DECRYPT_MODE, key);
			return new String(cipher.doFinal(obj));
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public byte[] EncryptHash(Key key) throws InvalidKeyException, IllegalBlockSizeException, 
	BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException {
		createHash();
//		System.out.println("hash: " + hash);
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		encHash = cipher.doFinal(hash.getBytes());
		return  encHash;
	}
	
	public String DecryptHash(Key key) throws InvalidKeyException, IllegalBlockSizeException, 
	BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException {
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(encHash));
	}
}
