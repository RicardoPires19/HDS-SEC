import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class verifyMac {

	
public byte[] createHmac(String input, Key sessionKey) throws Exception {
		 
		Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		sha256_HMAC.init(sessionKey);	
    byte[] result = sha256_HMAC.doFinal(input.getBytes());
    
    System.out.println(new String(result));
    return result;
    
}
public boolean verifyHMAC(byte[] encryptedMessage, Key sessionKey, String msg) throws InvalidKeyException, NoSuchAlgorithmException {

	Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
	sha256_HMAC.init(sessionKey);
	byte[] result = sha256_HMAC.doFinal(msg.getBytes());
	
	if(result == encryptedMessage) {
		return true;
		
	}
	else return false;	
}
}
