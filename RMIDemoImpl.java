
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.NoSuchPaddingException;

import AsymetricEncription.AsymmetricCryptography;
public class RMIDemoImpl extends UnicastRemoteObject implements RMIDemo{
	private static final long serialVersionUID = 1L;
	private final AsymmetricCryptography ac;
	private final MysqlCon db;
	
	protected RMIDemoImpl() throws RemoteException, NoSuchAlgorithmException, NoSuchPaddingException{
		super();
		ac = new AsymmetricCryptography();
		db = new MysqlCon();
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
	public String sendAmount(String src, String dst, String verification, int amount) throws RemoteException {
		if(!verifyKey(src, verification))
			return "NACK";
		
		int newBalance = db.getBalance(src) - amount;
		if(newBalance < 0)
			return "NACK";
		
		
		db.CreatePendingLedgerAndUpdateBalance(String src, String dst, int amount, int newBalance);
		//made a new one with both create ledger and update balance in order to ensure that they both happen or none of them happen	
		//db.updateBalance(src, balance);
		//db.createPendingLedger(src, dst, amount);
		
		return "ACK";
	}
	@Override
	public String receiveAmount(String src, String dst, String verification, int amount, int id) throws RemoteException {
		if(!verifyKey(dst, verification))
			return "NACK";
		
		AcceptTransactionAndUpdateBalance(dst, transaction_id);
		//db.updateBalance(dst, db.getBalance(dst) + amount);
		//db.createAcceptedLedger(src, dst, amount, id);
		
		return "ACK";
		
	}
	@Override
	public List<String> checkAccount(String pubKey, String verification) throws RemoteException {
		if(!verifyKey(pubKey, verification))
			return null;
		
		//ArrayList<String> account = new ArrayList<>(50);  WHY DO WE NEED THIS LIST?
		//String balance = Integer.toString(db.getBalance(pubKey)); 
		//account.add(balance);
		
		int balance = db.getBalance(pubKey); //returns int
		List<String> result = db.getIncomingPendingTransfers(pubKey); //returns a list of all pending request
		
		
		//return account;
	}
	@Override
	public List<String> audit(String pubKey) throws RemoteException {
		ArrayList<String> ledger = new ArrayList<>(50);
		
		//db.getIncomingPendingTransfers(pubKey);
		//FIX ME
		
		return ledger;
	}
	
}
