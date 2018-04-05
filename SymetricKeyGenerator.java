import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class SymetricKeyGenerator {
	private SecretKey secretKey;
	private Cipher cipher;
	
	public SymetricKeyGenerator(String secret, int length, String algorithm)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException {
		byte[] key = new byte[length];
		key = fixSecret(secret, length);
		this.secretKey = new SecretKeySpec(key, algorithm);
		this.cipher = Cipher.getInstance(algorithm);
	}
	
	public SymetricKeyGenerator(){}
	
	private byte[] fixSecret(String s, int length) throws UnsupportedEncodingException {
		if (s.length() < length) {
			int missingLength = length - s.length();
			for (int i = 0; i < missingLength; i++) {
				s += " ";
			}
		}
		return s.substring(0, length).getBytes("UTF-8");
	}
	
	public void renewKey(String secret, int length, String algorithm){
		try {
			byte[] key = new byte[length];
			key = fixSecret(secret, length);
			this.secretKey = new SecretKeySpec(key, algorithm);
			this.cipher = Cipher.getInstance(algorithm);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}
	
	public Cipher getSecretKey(){
		return cipher;
	}
	
	public byte[] Encrypt(byte[] msg){
		try {
			this.cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			return cipher.doFinal(msg);
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public byte[] Decrypt(byte[] msg){
		try {
			this.cipher.init(Cipher.DECRYPT_MODE, secretKey);
			return cipher.doFinal(msg);
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/*
	 * DEBUG
	public static void main(String[] args){
		byte[] test = "1234".getBytes();
		String secret = "SecretPassword";
		
		try {
			SymetricKeyGenerator sym = new SymetricKeyGenerator(secret, 16, "AES");
			
			byte[] aux = sym.Encrypt(test);
			System.out.println("aux: " + new String(aux));
			
			aux = sym.Decrypt(aux);
			System.out.println(new String(test) + " vs " + new String(aux));
			System.out.println(test + " vs " + aux);
			
		} catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
	
		
	}
	*/
}
