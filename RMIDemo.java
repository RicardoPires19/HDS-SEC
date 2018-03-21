
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;
public interface RMIDemo extends Remote {
	public String doCommunicate(String name) throws RemoteException;
	public String sendAmount(String src, String dst, String verification, int amount, String nonce) throws RemoteException;
	public String receiveAmount(String src, String dst, String verification, int amount, int id, String nonce) throws RemoteException;
	public List<String> checkAccount(String pubKey, String verification, String nonce) throws RemoteException;
	public List<String> audit(String pubKey) throws RemoteException;
}
