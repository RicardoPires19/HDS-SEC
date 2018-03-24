
import java.io.IOException;
import java.io.UnsupportedEncodingException;
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
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.sasl.AuthenticationException;

import AsymetricEncription.AsymmetricCryptography;

public class ClientLibrary extends UnicastRemoteObject implements Client{
	private static final long serialVersionUID = 1L;
	private final AsymmetricCryptography ac;
	private final SymetricKeyGenerator sc;
	private final MysqlCon db;
	private final KeyStore ks;
	private static final char[] PASSWORD = {'a', 'b'};
	private Map<String, Calendar> Sessions;
	private static final int SESSIONTIME = 5; //minutes

	protected ClientLibrary() throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, CertificateException, IOException{
		super();
		sc = new SymetricKeyGenerator();
		ac = new AsymmetricCryptography();
		db = new MysqlCon();
		ks = KeyStore.getInstance("JKS");
		java.io.FileInputStream fis = null;
		ks.load(fis, PASSWORD);
		Sessions = new HashMap<String, Calendar>(20);
	}

	public Cipher login(Key pubKey /*, String nonce, byte[] encNonce*/) throws AuthenticationException{ //byte[] encNonce is the output of createsignature
		String nonce = createNonce();
		byte [] encNonce = createSignature(nonce); //client signs the nonce, the client has its private key stored. 
		String check = ac.Decrypt(pubKey, encNonce); //server decrypts/verifies the signature
		if(!nonce.equals(check))
			throw new AuthenticationException("Could not authenticate");
		else{
			sc.renewKey(nonce, 16, "AES");
			Calendar date = Calendar.getInstance();
			date.setTime(new Date());
			date.add(Calendar.MINUTE, SESSIONTIME);
			Sessions.put(pubKey.toString(), date);
			return sc.getSecretKey(); //does this mean that the server sends the shared session key to the client?
			//also now the times should start to count down. 
		}
		//Where to add the creation of an hmac??
		//how to differentiate between the client and the server??
	}
	
	private boolean verifySession(String pubKey) {
		if(!Sessions.containsKey(pubKey))
			return false;
		
		Calendar now = Calendar.getInstance();
		now.setTime(new Date());
		if(Sessions.get(pubKey).getTimeInMillis() < now.getTimeInMillis())
			return false;
		
		
		return true;
	}

	public void logout(Key pubKey, String nonce, byte[] encNonce) throws AuthenticationException{
		String check = ac.Decrypt(pubKey, encNonce);
		if(!nonce.equals(check))
			throw new AuthenticationException("Could not authenticate");
		else{
			Sessions.remove(pubKey.toString());
		}
	}

	public boolean verifyHMAC(byte[] encryptedMessage, Key PublicsecretKey, String msg, SecretKey secretPrivateKey) {

		byte[] decryptedHMAC = ac.Decrypt(PublicsecretKey, encryptedMessage).getBytes(); //where do we get the key from??

		byte[] calculated_HMAC = getMac(msg, secretPrivateKey);

		if(decryptedHMAC.equals(calculated_HMAC)) {
			return true;
		}
		else return false;
	}

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

	private boolean verifyHash(String args, byte[] clientHash){ //Needs to verify the hash
		byte[] checkS;
		try {
			checkS = ac.createHash(args);
			byte[] checkC = sc.Decrypt(clientHash);
			
			return checkS.equals(checkC);
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		return false;
	}

	public byte[] createSignature(String input) {  //input can be both a nonce or a HMAC
		PrivateKey privateKey = kg.getPrivateKey();

		byte[] data = input.getBytes("UTF8");

		Signature sig = Signature.getInstance("SHA1WithRSA");
		sig.initSign(privateKey);
		sig.update(data);
		byte[] signatureBytes = sig.sign();
		//System.out.println("Signature:" + new BASE64Encoder().encode(signatureBytes));
		//String signature = new String(signatureBytes);
		return signatureBytes;
	}

	@Override
	public String register(Key key, String nonce, String signature) throws RemoteException {
		if(db.checkNonce(nonce, key)){
			return "This message has already been receiver";

		}

		if(db.checkClient(key)) {
			return "This public key is already registered";
		}


		String check = ac.Decrypt(key, signature.getBytes());
		if(!nonce.equals(check))
			return "you are not authorized to register";

		db.addNonce(key, nonce);
		db.createBalance(key, 100);
		//ledger.put(key, new ArrayList<String>()); //dunno how to make ledgers, doesn't matter, its just implement for the sql
		//balance.put(key, 5);

		return "\nWelcome " + key+ ", you are now registered";
	}

	@Override
	public String sendAmount(String src, String dst, byte[] verification, int amount, String nonce) throws RemoteException {
		if(db.checkNonce(nonce, src )){
			return "NACK";
		}
		else{
			db.addNonce(src, nonce);
		}	

		if(!verifyHash(""+src
						 +dst
						 +Integer.toString(amount)
						 +nonce, verification))
			return "NACK";
		else if(!verifySession(src))
			return "NACK";
		
		int newBalance = db.getBalance(src) - amount;
		if(newBalance < 0)
			return "NACK";

		db.CreatePendingLedgerAndUpdateBalance(src, dst, amount, newBalance);
		//made a new one with both create ledger and update balance in order to ensure that they both happen or none of them happen	

		return "ACK";
	}

	@Override
	public String receiveAmount(String src, String dst, byte[] verification, int amount, int id, String nonce) throws RemoteException {
		if(!verifyHash(""+src
						 +dst
						 +Integer.toString(amount)
						 +Integer.toString(id)
						 +nonce, verification))
			return "NACK";
		else if(!verifySession(dst))
			return "NACK";

		db.AcceptTransactionAndUpdateBalance(dst, id);
		return "ACK";
	}
	
	@Override
	public List<String> checkAccount(String pubKey, byte[] verification, String nonce) throws RemoteException {
		if(!verifyHash(""+pubKey.toString()+nonce, verification))
			return null;
		else if(!verifySession(pubKey))
			return null;

		int balance = db.getBalance(pubKey); //returns int
		List<String> result = db.getIncomingPendingTransfers(pubKey); //returns a list of all pending request
		result.add(Integer.toString(balance));

		return result;
	}
	
	@Override
	public List<String> audit(String pubKey) throws RemoteException {
		List<String> output = db.getAllTransfers(pubKey);
		return output;
	}

}
