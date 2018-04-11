package common;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;

public class verifyMac {


	public byte[] createHmac(String input, Key sessionKey) throws Exception {

		Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		sha256_HMAC.init(sessionKey);	
		byte[] result = sha256_HMAC.doFinal(input.getBytes("UTF-8"));

//		System.out.println(new String(result));
		return result;

	}
	public boolean verifyHMAC(byte[] encryptedMessage, Key sessionKey, String msg) throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, UnsupportedEncodingException {

		Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		sha256_HMAC.init(sessionKey);	
		byte[] result = sha256_HMAC.doFinal(msg.getBytes("UTF-8"));

//		System.out.println(new String(result));
		if(Arrays.equals(encryptedMessage, result)) {
			return true;
		}
		else 
			return false;	
	}
	public static void main(String[] args) {
		SymetricKeyGenerator sc = new SymetricKeyGenerator();
		sc.renewKey("test", 1024, "AES");
		verifyMac vm = new verifyMac();
		
		
		String test1 = "testString";
		try {
			byte[] test = vm.createHmac(test1, sc.getSecretKey());
			boolean result = vm.verifyHMAC(test, sc.getSecretKey(), test1);
			System.out.println("result: " + result);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
