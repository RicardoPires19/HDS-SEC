
import java.rmi.Naming;
public class RMIClient {
	public static void main(String[] args) throws Exception{
		if (args.length == 2) {
			String url = new String("rmi://"+args[0]+"/RMIDemo");
			Client rMIDemo = (Client)Naming.lookup(url);
			String serverReply = rMIDemo.doCommunicate(args[1]);
			System.out.println("Server Reply: "+serverReply);
			
		}else {
			System.err.println("Usage: RMIDemoClient <server> <name>");
		}
	}
	
}
