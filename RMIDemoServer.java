
import java.rmi.Naming;
public class RMIDemoServer {
	public static void main (String[] args) throws Exception{
	java.rmi.registry.LocateRegistry.createRegistry(1099);
	RMIDemoImpl rMIDemoImpl = new RMIDemoImpl();
	Naming.rebind("RMIDemo", rMIDemoImpl);
	System.out.println("RMIDemo object bound to the name 'RMIDemo' and is ready for use..");
	
	//POPULATE//
	System.out.println(rMIDemoImpl.register("paneleiro"));
	System.out.println(rMIDemoImpl.register("rabeta"));
	}
}
