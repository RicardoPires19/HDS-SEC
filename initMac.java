import java.security.*;
import javax.crypto.*;


public class initMac {

        public String getMac(String input, SecretKey sk) throws Exception {
                // Generate secret key for HmacSHA256
                //KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
                //SecretKey sk = kg.generateKey();

                // Get instance of Mac object implementing HmacSHA256, and
                // initialize it with the above secret key
                Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
                sha256_HMAC.init(sk);
                byte[] result = sha256_HMAC.doFinal(input.getBytes());
            
            System.out.println(new String(result));
            return result;
            
        }
        
        
       
        
      
    }
