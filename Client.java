
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.*;
import java.sql.SQLException;
import java.util.*;

public interface Client extends Remote {
	public String sendAmount(PublicKey src, PublicKey dst, int amount, String nonce,byte[] signature) throws RemoteException;
	public String receiveAmount(PublicKey pubKey, int id, String nonce,byte[] signature) throws RemoteException;
	public String checkAccount(PublicKey pubKey, String nonce, byte[] signature,byte[] cHash) throws RemoteException;
	public String audit(PublicKey pubKey,String audited, String nonce, byte[] signature) throws RemoteException;
	
	public String register(PublicKey pubKey, String nonce, byte[] signature) throws RemoteException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException;
	
	public String createNonce(PublicKey pubKey) throws RemoteException;
	public List<String> getPublicKeys(PublicKey pubKey) throws RemoteException, SQLException;
	public List<String> getPendingList(PublicKey pubKey) throws RemoteException, SQLException;
}