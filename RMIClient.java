
import java.rmi.Naming;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

import AsymetricEncription.AsymmetricCryptography;

@SuppressWarnings("unused")
public class RMIClient {
	private AsymmetricCryptography ac;
	
	public RMIClient() {
		try {
			ac = new AsymmetricCryptography();
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) throws Exception{
		if (args.length == 2) {
			String url = new String("rmi://"+args[0]+"/RMIDemo");
			Client rMIDemo = (Client)Naming.lookup(url);
//			String serverReply = rMIDemo.doCommunicate(args[1]);
//			System.out.println("Server Reply: "+serverReply);
			
		}else {
			System.err.println("Usage: RMIDemoClient <server> <name>");
		}
	}
	
}
