
import java.rmi.Naming;
public class Server{
	public static void main (String[] args) throws Exception{
	ClientLibrary rMIDemoImpl = new ClientLibrary();
	Naming.rebind("RMIDemo", rMIDemoImpl);
	System.out.println("RMIDemo object bound to the name 'RMIDemo' and is ready for use..");
	}
}
