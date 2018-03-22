import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class verifyMac {

	
	private static final boolean True = false;
	private static final boolean False = false;

	
	//String hmac is the hmac that is sent from a client
	public boolean verifyhmac(String nonce, SecretKey sk, String hmac) throws Exception {
		//get the nonce and the hmac of the nonce, use the shared key to verify that the hmac received is the same as the one you calculate
		
		Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		sha256_HMAC.init(sk);
		byte[] result = sha256_HMAC.doFinal(nonce.getBytes());
		//String calc_hmac = new String(result);
		
		
		byte[] hmac_rec = hmac.getBytes();
		
		//initMac rec_hmac = new initMac();
		
		//String receive = rec_hmac.getMac(nonce, sk);
		
		if(result == hmac_rec) {
			return True;
			
		}
		else return False;
    
   
		
		
	}
	
}
