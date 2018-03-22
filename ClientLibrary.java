
import java.io.IOException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import AsymetricEncription.AsymmetricCryptography;

public class ClientLibrary extends UnicastRemoteObject implements Client{
	private static final long serialVersionUID = 1L;
	private final AsymmetricCryptography ac;
	private final MysqlCon db;
	private final KeyStore ks;
	private static final char[] PASSWORD = {'a', 'b'};
	
	protected ClientLibrary() throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, CertificateException, IOException{
		super();
		ac = new AsymmetricCryptography();
		db = new MysqlCon();
		ks = KeyStore.getInstance("JKS");
		java.io.FileInputStream fis = null;
	    ks.load(fis, PASSWORD);
	}
	

	private void storeKey(String pubKey, SecretKey clientKey){
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(PASSWORD);
		KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(clientKey);
		try {
			ks.setEntry(pubKey, skEntry, protParam);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	}
	
	private SecretKey getKey(String pubKey){
		try {
			KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(PASSWORD);
			KeyStore.SecretKeyEntry skEntry = (SecretKeyEntry) ks.getEntry("privateKeyAlias", protParam);
			return skEntry.getSecretKey();
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}

	 public String createNonce() {
	        	SecureRandom nonce = new SecureRandom();
	        	String Nonce = nonce.toString();
	        	return Nonce;
    }
	
	private boolean verifyKey(String pubKey, String ver){
		byte[] verification = ver.getBytes();
		byte[] publicBytes = pubKey.getBytes();
		
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
		KeyFactory keyFactory;
		
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			PublicKey pubKey1 = keyFactory.generatePublic(keySpec);
			String result = ac.Decrypt(pubKey1, verification);
			return pubKey.equals(result);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			return false;
		}
	}
	
	public String doCommunicate (String name) throws RemoteException{
		return "\nServer says: Hi " +name+ "\n";
	}
	@Override
	public String sendAmount(String src, String dst, String verification, int amount, String nonce) throws RemoteException {
		if(db.checkNonce(nonce, src )){
			return "NACK";
		}
		else{
			db.addNonce(src, nonce);
			//return "ACK"
		}	
		
		if(!verifyKey(src, verification))
			return "NACK";
		
		int newBalance = db.getBalance(src) - amount;
		if(newBalance < 0)
			return "NACK";
		
		
		db.CreatePendingLedgerAndUpdateBalance(src, dst, amount, newBalance);
		//made a new one with both create ledger and update balance in order to ensure that they both happen or none of them happen	
		//db.updateBalance(src, balance);
		//db.createPendingLedger(src, dst, amount);
		
		return "ACK";
	}
		
	@Override
	public String receiveAmount(String src, String dst, String verification, int amount, int id, String nonce) throws RemoteException {
		if(!verifyKey(dst, verification))
			return "NACK";
		
		db.AcceptTransactionAndUpdateBalance(dst, id);
		//db.updateBalance(dst, db.getBalance(dst) + amount);
		//db.createAcceptedLedger(src, dst, amount, id);
		
		return "ACK";
		
	}
	@Override
	public List<String> checkAccount(String pubKey, String verification, String nonce) throws RemoteException {
		if(!verifyKey(pubKey, verification))
			return null;
		
		//ArrayList<String> account = new ArrayList<>(50);  WHY DO WE NEED THIS LIST?
		//String balance = Integer.toString(db.getBalance(pubKey)); 
		//account.add(balance);
		
		int balance = db.getBalance(pubKey); //returns int
		List<String> result = db.getIncomingPendingTransfers(pubKey); //returns a list of all pending request
		result.add(Integer.toString(balance));
		
		
		return result;
		
		
		//return account;
	}
	@Override
	public List<String> audit(String pubKey) throws RemoteException {
		//ArrayList<String> ledger = new ArrayList<>(50);
		
		List<String> output = db.getAllTransfers(pubKey);
		//db.getIncomingPendingTransfers(pubKey);
		//FIX ME
		
		//return ledger;
		return output;
	}

		
	
}
