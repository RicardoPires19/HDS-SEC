
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.sql.SQLException;
import java.util.List;

import javax.crypto.SecretKey;
import javax.security.sasl.AuthenticationException;

public interface Client extends Remote {
	public String audit(PublicKey pubKey,String audited, String nonce, byte[] signature) throws RemoteException;

	public SecretKey register(PublicKey pubKey, String nonce, byte[] signature) throws RemoteException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, AuthenticationException;

	public String createNonce(PublicKey pubKey) throws RemoteException;
	public List<String> getPublicKeys(PublicKey pubKey) throws RemoteException, SQLException;
	public List<String> getPendingList(PublicKey pubKey) throws RemoteException, SQLException;
	public String sendAmount(PublicKey src, PublicKey dst, int amount, String nonce, byte[] bs) throws RemoteException, AuthenticationException;
	public String receiveAmount(PublicKey pubKey, int id, String nonce, byte[] bs) throws RemoteException, AuthenticationException;
	public String checkAccount(PublicKey pubKey, String nonce, byte[] bs) throws RemoteException, AuthenticationException;
}