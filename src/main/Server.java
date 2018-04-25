package main;

import java.rmi.Naming;
public class Server{
	public static void main (String[] args) throws Exception{
	java.rmi.registry.LocateRegistry.createRegistry(1098);
	ServerLibrary RMIDemoImpl = new ServerLibrary(args[1]);
	Naming.rebind("ServerLibrary", RMIDemoImpl);
	System.out.println("ServerLibrary object bound to the name 'ServerLibrary' and is ready for use..");
	}
}
