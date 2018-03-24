
import java.io.IOException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.Key;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import AsymetricEncription.AsymmetricCryptography;

public class ClientLibrary extends UnicastRemoteObject implements Client{
	private static final long serialVersionUID = 1L;
	private final AsymmetricCryptography ac;
	private final SymetricKeyGenerator sc;
	private final MysqlCon db;
	private final KeyStore ks;
	private static final char[] PASSWORD = {'a', 'b'};
	private Map<String, Integer> Sessions;
	
	protected ClientLibrary() throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, CertificateException, IOException{
		super();
		sc = new SymetricKeyGenerator();
		ac = new AsymmetricCryptography();
		db = new MysqlCon();
		ks = KeyStore.getInstance("JKS");
		java.io.FileInputStream fis = null;
	    ks.load(fis, PASSWORD);
	    Sessions = new HashMap<String, Integer>(20);
	}
	
	public Cipher login(Key pubKey /*, String nonce, byte[] encNonce*/){ //byte[] encNonce is the output of createsignature
		String nonce = createNonce();
		byte [] encNonce = createSignature(nonce); //client signs the nonce, the client has its private key stored. 
		String check = ac.Decrypt(pubKey, encNonce); //server decrypts/veryfies the signature
		if(!nonce.equals(check))
			return "Could not authenticate";
		else{
			sc.renewKey(nonce, 16, "AES");
			Sessions.put(pubKey.toString(), 300);
			return sc.getSecretKey(); //does this mean that the server sends the shared session key to the client?
			//also now the times should start to count down. 
		}
		//Where to add the creation of an hmac??
		//how to differentiate between the client and the server??
	}
	
	public void logout(Key pubKey, String nonce, byte[] encNonce){
		String check = ac.Decrypt(pubKey, encNonce);
		if(!nonce.equals(check))
			;
		else{
			Sessions.remove(pubKey.toString());
		}
	}
	
	public void Counter(){}
	

	@SuppressWarnings("unused")
	private void storeKey(String pubKey, SecretKey clientKey){
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(PASSWORD);
		KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(clientKey);
		try {
			ks.setEntry(pubKey, skEntry, protParam);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	}
	
	@SuppressWarnings("unused")
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
	
	private boolean verifyKey(String pubKey, String ver){ //dont really understand how this is working??
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
	
	public byte[] createSignature(String input) {  //input can be both a nonce or a HMAC
		 PrivateKey privateKey = kg.getPrivateKey();
	
	     byte[] data = input.getBytes("UTF8");
	
	     Signature sig = Signature.getInstance("SHA1WithRSA");
	     sig.initSign(privateKey);
	     sig.update(data);
	     byte[] signatureBytes = sig.sign();
	     //System.out.println("Singature:" + new BASE64Encoder().encode(signatureBytes));
	     //String signature = new String(signatureBytes);
	     return signatureBytes;
	}
	
	public String doCommunicate (String name) throws RemoteException{
		return "\nServer says: Hi " +name+ "\n";
	}
	
	@Override
	public String register(String key, String nonce, String signature) throws RemoteException {
	if(db.checkNonce(nonce, key)){
		return "This message has already been receiver";

	}

	if(db.checkClient(key)) {
		return "This public key is already registered";
	}


	String check = ac.Decrypt(key, signature);
	if(!nonce.equals(check))
		return "you are not authorized to register";

	db.addNonce(key, nonce);
	db.createBalance(key, 100);
	//ledger.put(key, new ArrayList<String>()); //dunno how to make ledgers, doesnt matter, its just implement for the sql
	//balance.put(key, 5);

	return "\nWelcome " + key+ ", you are now registered";
	}
	}

	
	
	@Override
	public String sendAmount(String src, String dst, int amount, String nonce, String verification) throws RemoteException {
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
