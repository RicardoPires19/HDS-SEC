
import java.rmi.Naming;
public class RMIDemoClient {
	public static void main(String[] args) throws Exception{
		if (args.length == 2) {
			String url = new String("rmi://"+args[0]+"/RMIDemo");
			RMIDemo rMIDemo = (RMIDemo)Naming.lookup(url);
			String serverReply = rMIDemo.doCommunicate(args[1]);
			System.out.println("Server Reply: "+serverReply);
			
		}else {
			System.err.println("Usage: RMIDemoClient <server> <name>");
		}
	}
	
	//SecureRandom nonce = new SecureRandom();
	//	String Nonce = nonce.toString();
	//FIX: WHERE TO CREATE THE NONCE?
}
