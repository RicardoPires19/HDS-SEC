package main;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.sql.SQLException;
import java.util.List;

import javax.crypto.IllegalBlockSizeException;
import javax.security.sasl.AuthenticationException;

public interface Client extends Remote {
	
	public byte[] login(PublicKey pubKey,String nounce,byte[] signature) throws RemoteException, AuthenticationException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IllegalBlockSizeException;	
	public void logout(PublicKey pubKey,String nonce, byte[] signature) throws RemoteException, AuthenticationException, InvalidKeyException, NoSuchAlgorithmException, SignatureException;
	public byte[] register(PublicKey pubKey, String nonce, byte[] signature) throws RemoteException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, AuthenticationException, IllegalBlockSizeException;
	public byte[][] sendAmount(PublicKey src, String dst, int amount, String nonce, byte[] bs, byte[] hmac) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, Exception;
	public byte[][] receiveAmount(PublicKey pubKey, int id, String nonce, byte[] bs) throws RemoteException, AuthenticationException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, Exception;
	public byte[][] checkAccount(PublicKey pubKey, String nonce, byte[] bs) throws RemoteException, AuthenticationException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, Exception;
	public String audit(PublicKey pubKey,String audited, String nonce) throws RemoteException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, Exception;

	public String createNonce(PublicKey pubKey) throws RemoteException;
	public List<String> getPublicKeys(PublicKey pubKey) throws RemoteException, SQLException;
	public List<String> getPendingList(PublicKey pubKey) throws RemoteException, SQLException;
}