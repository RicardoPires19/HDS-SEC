
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLException;
import java.util.ArrayList;
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

	protected ClientLibrary() throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, CertificateException, IOException, NoSuchProviderException{
		super();
		akg = new AsymmetricKeyGenerator(512, "ServerKey");
		sc = new SymetricKeyGenerator();
		ac = new AsymmetricCryptography();
		db = new MysqlCon();
		ks = KeyStore.getInstance("JKS");
		java.io.FileInputStream fis = null;
		ks.load(fis, PASSWORD);
		Sessions = new HashMap<String, Calendar>(20);
	}

	public Cipher login(Key pubKey /*, String nonce, byte[] encNonce*/) throws AuthenticationException{ //byte[] encNonce is the output of createsignature
		//String nonce = createNonce();
		//byte [] encNonce = createSignature(nonce); //client signs the nonce, the client has its private key stored. 
//		String check = ac.Decrypt(pubKey, encNonce); //server decrypts/verifies the signature
//		String nonce = getNonce(pubKey);
//		if(!nonce.equals(check))
//			throw new AuthenticationException("Could not authenticate");
//		else{
//			sc.renewKey(nonce, 16, "AES");
			Calendar date = Calendar.getInstance();
			date.setTime(new Date());
			date.add(Calendar.MINUTE, SESSIONTIME);
			Sessions.put(pubKey.toString(), date);
			return sc.getSecretKey();
	}

	public void logout(Key pubKey, String nonce, byte[] encNonce) throws AuthenticationException{
		String check = ac.Decrypt(pubKey, encNonce);
		if(!nonce.equals(check))
			throw new AuthenticationException("Could not authenticate");
		else{
			Sessions.remove(pubKey.toString());
		}
	}

	@Override
	public String register(PublicKey pubKey, String nonce, byte[] signature,byte[] cHash) throws RemoteException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
		if(!verifySignature(pubKey,nonce,signature)){
			return "This mensage was tampered";
		}
		
		if(!verifyHash(pubKey.toString(), cHash))
			return "This message has been tampered with";
		
		if(db.checkNonce(nonce, pubKey.toString())){
			return "This message has already been received";
		}

		if(db.checkClient(pubKey.toString())) {
			return "Welcome Back";
		}
		
		
	    
		db.addNonce(pubKey.toString(), nonce.toString());
		db.AddClient(pubKey.toString(), 100);
//		ledger.put(key, new ArrayList<String>()); //dunno how to make ledgers, doesn't matter, its just implement for the sql
//		balance.put(key, 5);

		return "\nWelcome sir/milady , you are now registered check your balance ;)";
	}
	
	@Override
	public String checkAccount(PublicKey pubKey, String nonce,  byte[] signature, byte[] cHash) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		if(!verifySignature(pubKey,nonce,signature)){
			return "This mensage was tampered";
		}
		
		if(!verifyHash(pubKey.toString(), cHash))
			return "This message has been tampered with";
		
		if(db.checkNonce(nonce, pubKey.toString())){
			return "This message has already been received";

		}
		
		String serverReply = "";

//		if(!verifySession(pubKey))
//			return null;
		
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

		return serverReply;
	}
	
	@Override
	public String sendAmount(PublicKey src, PublicKey dst, int amount, String nonce,byte[] signature,byte[] cHash) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		if(!verifySignature(src,nonce,signature)){
			return "This mensage was tampered";
		}
		
		if(!verifyHash(src.toString(), cHash))
			return "This message has been tampered with";
		
		if(db.checkNonce(nonce, src.toString())){
			return "This message has already been received";

		}
		
		db.addNonce(src.toString(), nonce);
		
		int newBalance = db.getBalance(src.toString()) - amount;
		if(newBalance < 0)
			return "WARNING: Insuficient balance!";

		db.CreatePendingLedgerAndUpdateBalance(src.toString(), dst.toString(), amount, newBalance);
		//made a new one with both create ledger and update balance in order to ensure that they both happen or none of them happen	
		System.out.println("SENDAMOUNT SUCCESS");
		return "Sucess, transaction is now pending";
	}

	@Override
	public String receiveAmount(PublicKey pubKey, int id, String nonce, byte[] signature,byte[] cHash) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		if(!verifySignature(pubKey,nonce,signature)){
			return "This mensage was tampered";
		}
		
		if(!verifyHash(pubKey.toString(), cHash))
			return "This message has been tampered with";
		
		if(db.checkNonce(nonce, pubKey.toString())){
			return "This message has already been received";

		}
		
		db.AcceptTransactionAndUpdateBalance(pubKey.toString(), id);
		return "ACK";
	}
		
	@Override
	public String audit(PublicKey pubKey,String audited, String nonce, byte[] signature,byte[] cHash) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		if(!verifySignature(pubKey,nonce,signature)){
			return "This mensage was tampered";
		}
		
		if(!verifyHash(pubKey.toString(), cHash))
			return "This message has been tampered with";
		
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
	
	//USED TO PROVIDE USER A LIST OF KEYS TO SEND AMOUNT
	@Override
	public List<String> getPublicKeys(PublicKey pubKey) throws RemoteException, SQLException{
		List<String> output = db.getAllPublicKeys();
		return output;
	}
	
	//USED TO PROVIDE USER A LIST OF PENDING TRANSACTIONS FOR THE USER TO ACCEPT
	public List<String> getPendingList(PublicKey pubKey) throws RemoteException, SQLException{
		List<String> output = db.pedingTransactionsList(pubKey.toString());
		return output;
	}
	
	private boolean verifySession(PublicKey pubKey) {
		if(!Sessions.containsKey(pubKey))
			return false;
		
		Calendar now = Calendar.getInstance();
		now.setTime(new Date());
		if(Sessions.get(pubKey).getTimeInMillis() < now.getTimeInMillis())
			return false;
		
		
		return true;
	}
	
	public boolean verifyHMAC(byte[] encryptedMessage, Key PublicsecretKey, String msg, SecretKey secretPrivateKey) {

//		byte[] decryptedHMAC = ac.Decrypt(PublicsecretKey, encryptedMessage).getBytes(); //where do we get the key from??
//
//		byte[] calculated_HMAC = getMac(msg, secretPrivateKey);
//
//		if(decryptedHMAC.equals(calculated_HMAC)) {
//			return true;
//		}
//		else return false;
		return true;
	}

	@Override
	public String createNonce(PublicKey pubKey) {
		String Nonce = Integer.toString(nonce.nextInt());
		return Nonce;
	}
	
	private boolean verifySignature(PublicKey pubKey, String nonce, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initVerify(pubKey);
		sig.update(nonce.getBytes());
		if(!sig.verify(signature))
			return false;
		
		return true;

	}
	
	private boolean verifyHash(String args, byte[] clientHash){ //Needs to verify the hash
		
	    MessageDigest md;
		try {
			md = MessageDigest.getInstance("MD5");
		    md.update(args.getBytes());
		    byte[] serverHash = md.digest();	
		    if(!MessageDigest.isEqual(serverHash, clientHash)){
		    	return false;
		    }
		    
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return false;
		}
		return true;
	}

}
