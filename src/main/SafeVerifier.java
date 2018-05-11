package main;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;

public interface SafeVerifier extends Remote {
	public void sendInput(String input, PublicKey pubkey, byte[] signature) throws RemoteException;
	public byte[][] verifyInput() throws RemoteException;
}
