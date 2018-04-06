import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.sasl.AuthenticationException;

import AsymetricEncription.AsymmetricCryptography;
import AsymetricEncription.AsymmetricKeyGenerator;

public class ClientLibrary extends UnicastRemoteObject implements Client{
	private static final long serialVersionUID = 1L;
	private final AsymmetricCryptography ac;
	private final AsymmetricKeyGenerator akg;
	private final SymetricKeyGenerator sc;
	private final MysqlCon db;
	private final KeyStore ks;
	private static final char[] PASSWORD = {'a', 'b'};
	private Map<String, Calendar> Sessions;
	private static final int SESSIONTIME = 5; //minutes
	private final SecureRandom nonce = new SecureRandom();
	private final verifyMac macVerifier = new verifyMac();
	private final SecureRandom random;
	

	protected ClientLibrary() throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, CertificateException, IOException, NoSuchProviderException{
		super();
		akg = new AsymmetricKeyGenerator(512, "ServerKey");
		sc = new SymetricKeyGenerator();
		ac = new AsymmetricCryptography();
		db = new MysqlCon();
		ks = KeyStore.getInstance("JCEKS");
		java.io.FileInputStream fis = null;
		ks.load(fis, PASSWORD);
		Sessions = new HashMap<String, Calendar>(20);
		random = new SecureRandom();
		random.setSeed("RANDOMseeds".getBytes());

	}

	private boolean verifySession(PublicKey pubKey) {
		if(!Sessions.containsKey(pubKey.toString()))
			return false;

		Calendar now = Calendar.getInstance();
		now.setTime(new Date());
		if(Sessions.get(pubKey.toString()).getTimeInMillis() < now.getTimeInMillis())
			return false;

		return true;
	}
	
	private void storeKey(PublicKey pubKey, SecretKey clientKey){
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(PASSWORD);
		KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(clientKey);
		try {
			ks.setEntry(pubKey.toString(), skEntry, protParam);
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

	@Override
	public String createNonce(PublicKey pubKey) {
		String Nonce = Integer.toString(nonce.nextInt());
		return Nonce;
	}
	
	public void logout(PublicKey pubKey, String nonce, byte[] signature) throws AuthenticationException, InvalidKeyException, NoSuchAlgorithmException, SignatureException{
		if(!verifySignature(pubKey,nonce,signature)){
			throw new AuthenticationException("You are not authorized to log in");
		}
		else{
			Sessions.remove(pubKey.toString());
		}
	}
	
	public SecretKey login(PublicKey pubKey,String nounce, byte[] signature) throws AuthenticationException, NoSuchAlgorithmException, InvalidKeyException, SignatureException{ //byte[] encNonce is the output of createsignature

		if(!verifySignature(pubKey,nounce,signature))
			throw new AuthenticationException("You are not authorized to log in");

		if (!db.checkClient(pubKey.toString()))
			throw new AuthenticationException("This user does not exist, please register or try again");

		Calendar date = Calendar.getInstance();
		date.setTime(new Date());
		date.add(Calendar.MINUTE, SESSIONTIME);
		Sessions.put(pubKey.toString(), date);
		sc.renewKey(Integer.toString(random.nextInt()), 16, "AES");
		storeKey(pubKey, sc.getSecretKey());
		return sc.getSecretKey();
	}

	@Override
	public SecretKey register(PublicKey pubKey, String nonce, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, AuthenticationException {
		if(db.checkNonce(nonce, pubKey.toString())){
			throw new AuthenticationException("This message has already been received");
		}
		if(!verifySignature(pubKey,nonce,signature)){
			throw new AuthenticationException("You are not authorized to log in");
		}
		
		if(db.checkClient(pubKey.toString())) {
			throw new AuthenticationException("This public key is already registered");
		}
		db.addNonce(pubKey.toString(), nonce.toString());
		db.AddClient(pubKey.toString(), 100);
		//		ledger.put(key, new ArrayList<String>()); //dunno how to make ledgers, doesn't matter, its just implement for the sql
		//		balance.put(key, 5);

		Calendar date = Calendar.getInstance();
		date.setTime(new Date());
		date.add(Calendar.MINUTE, SESSIONTIME);
		Sessions.put(pubKey.toString(), date);
		sc.renewKey(Integer.toString(random.nextInt()), 16, "AES");
		storeKey(pubKey, sc.getSecretKey());
		
		return sc.getSecretKey();
	}

	@Override
	public String checkAccount(PublicKey pubKey, String nonce,  byte[] hmac) throws RemoteException, AuthenticationException {
		if(db.checkNonce(nonce, pubKey.toString())){
			return "This message has already been received";
		}
		String serverReply = "";

		if(!verifySession(pubKey))
			return "Not in Session";

		try {
			macVerifier.verifyHMAC(hmac, ks.getKey(pubKey.toString(), PASSWORD), nonce);
		} catch (Exception e) {
			throw new AuthenticationException("Could not authenticate");
		}


		int balance = db.getBalance(pubKey.toString()); //returns int
		serverReply = serverReply + "Your balance is:\n "+ Integer.toString(balance);
		List<String> result = db.getIncomingPendingTransfers(pubKey.toString()); //returns a list of all pending request
		if(result.isEmpty()){
			return serverReply;
		}
		else{
			serverReply = serverReply + "\nYou have the following pending:";
			for(String str: result){
				serverReply = serverReply + "\n" +str;	
			}
		}
		System.out.println(serverReply.toString());
		return serverReply;
	}

	@Override
	public String sendAmount(PublicKey src, String dst, int amount, String nonce, byte[] hmac) throws RemoteException, AuthenticationException {
		if(db.checkNonce(nonce, src.toString())){
			return "This message has already been received";

		}
		//		if(db.checkNonce(nonce, src.toString())){
		//			return "NACK";
		//		}
		//		else{
		//			db.addNonce(src.toString(), nonce);
		//		}	
		//
		if(!verifySession(src))
			return "Not in Session";

		try {
			macVerifier.verifyHMAC(hmac, ks.getKey(src.toString(), PASSWORD), nonce);
		} catch (Exception e) {
			throw new AuthenticationException("Could not authenticate");
		}

		int newBalance = db.getBalance(src.toString()) - amount;
		if(newBalance < 0)
			return "WARNING: Insuficient balance!";

		db.CreatePendingLedgerAndUpdateBalance(src.toString(), dst, amount, newBalance);
		//made a new one with both create ledger and update balance in order to ensure that they both happen or none of them happen	

		return "Sucess, transaction is now pending";
	}

	@Override
	public String receiveAmount(PublicKey pubKey, int id, String nonce, byte[] hmac) throws RemoteException, AuthenticationException {
		if(db.checkNonce(nonce, pubKey.toString())){
			return "This message has already been received";
		}
		if(!verifySession(pubKey))
			return "Not in Session";
		try {
			macVerifier.verifyHMAC(hmac, ks.getKey(pubKey.toString(), PASSWORD), nonce);
		} catch (Exception e) {
			throw new AuthenticationException("Could not authenticate");
		}

		db.AcceptTransactionAndUpdateBalance(pubKey.toString(), id);
		return "TCHATCHING, check your new balance";
	}	

	@Override
	public String audit(PublicKey pubKey,String audited, String nonce, byte[] signature) throws RemoteException {
		if(db.checkNonce(nonce, pubKey.toString())){
			return "This message has already been received";
		}
		List<String> output = db.getAllTransfers(audited);
		String serverReply = "";
		for(String str: output){
			serverReply = serverReply + str + "\n";
		}
		return serverReply;
	}

	@Override
	public List<String> getPublicKeys(PublicKey pubKey) throws RemoteException, SQLException{
		List<String> output = db.getAllPublicKeys();
		return output;
	}
	@Override
	public List<String> getPendingList(PublicKey pubKey) throws RemoteException, SQLException{
		List<String> output = db.pedingTransactionsList(pubKey.toString());
		return output;
	}
	
	private boolean verifySignature(PublicKey pubKey, String nonce, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initVerify(pubKey);
		sig.update(nonce.getBytes());
		if(!sig.verify(signature))
			return false;
		
		return true;

	}

}