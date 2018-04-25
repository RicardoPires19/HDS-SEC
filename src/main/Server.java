package main;

import java.rmi.Naming;
public class Server{
	public static void main (String[] args) throws Exception{
		int	n = Integer.parseInt(args[0]);
		java.rmi.registry.LocateRegistry.createRegistry(1099);

		for (int i = 0; i < n; i++) {
			Naming.rebind("rmi://localhost/Server" + i, new ServerLibrary("Server" + i));
		}
		
		for (String string : Naming.list("localhost")) {
			System.out.println(string);
		}
		
		System.out.println(n + " servers launched and ready for requests.");
	}
}
