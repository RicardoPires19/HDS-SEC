
import java.rmi.Naming;
public class Server{
	public static void main (String[] args) throws Exception{
	java.rmi.registry.LocateRegistry.createRegistry(1099);
	ClientLibrary RMIDemoImpl = new ClientLibrary();
	Naming.rebind("RMIDemo", RMIDemoImpl);
	System.out.println("RMIDemo object bound to the name 'RMIDemo' and is ready for use..");
	}
}
