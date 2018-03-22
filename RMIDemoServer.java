
import java.rmi.Naming;
public class RMIDemoServer {
	public static void main (String[] args) throws Exception{
	RMIDemoImpl rMIDemoImpl = new RMIDemoImpl();
	Naming.rebind("RMIDemo", rMIDemoImpl);
	System.out.println("RMIDemo object bound to the name 'RMIDemo' and is ready for use..");
	}
}
