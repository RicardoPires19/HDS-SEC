
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.Key;
import java.util.List;
public interface Client extends Remote {
	public String sendAmount(String src, String dst, byte[] verification, int amount, String nonce) throws RemoteException;
	public String receiveAmount(String src, String dst, byte[] verification, int amount, int id, String nonce) throws RemoteException;
	public List<String> checkAccount(String pubKey, byte[] verification, String nonce) throws RemoteException;
	public List<String> audit(String pubKey) throws RemoteException;
	String register(Key key, String nonce, String signature) throws RemoteException;
}
