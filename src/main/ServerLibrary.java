package main;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.sasl.AuthenticationException;

import common.AsymmetricCryptography;
import common.AsymmetricKeyGenerator;
import common.SymetricKeyGenerator;
import common.verifyMac;

public class ServerLibrary extends UnicastRemoteObject implements Client{
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

	public ServerLibrary() throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, CertificateException, IOException, NoSuchProviderException{
		super();
		akg = new AsymmetricKeyGenerator(512, "ServerKey");
		ac = new AsymmetricCryptography();
		akg.createKeyPair();
		akg.WritePublicKey("PKI/" + akg.getKeyName());   // PKI directory is the fictitious Public Key Infrastructure
		sc = new SymetricKeyGenerator();
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

	public byte[] createSignature(String input) {  //input can be both a nonce or a HMAC
		PrivateKey privateKey = akg.getPrivateKey();

		byte[] data;
		try {
			data = input.getBytes("UTF8");
			Signature sig = Signature.getInstance("SHA1WithRSA");
			sig.initSign(privateKey);
			sig.update(data);
			byte[] signatureBytes = sig.sign();
			return signatureBytes;
		} catch (UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public void logout(PublicKey pubKey, String nonce, byte[] signature) throws RemoteException, AuthenticationException, NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		if(db.checkNonce(nonce, pubKey.toString()))
			throw new AuthenticationException("Could not authenticate");
		else{
			db.addNonce(pubKey.toString(), nonce);
		}	
		if(!verifySignature(pubKey,nonce,signature))
			throw new AuthenticationException("You are not authorized to log out");
		else{
			Sessions.remove(pubKey.toString());
		}

	}



	public byte[] login(PublicKey pubKey, String nonce, byte[] signature) throws AuthenticationException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IllegalBlockSizeException{ //byte[] encNonce is the output of createsignature
		if(db.checkNonce(nonce, pubKey.toString())){
			throw new AuthenticationException("This message has already been received");
		}
		db.addNonce(pubKey.toString(), nonce.toString());

		if(!db.checkClient(pubKey.toString())) {
			throw new AuthenticationException("This public key is not registered");
		}

		Signature sig = Signature.getInstance("SHA1withRSA"); //verifies the signature of the nonce
		sig.initVerify(pubKey);
		sig.update(nonce.getBytes());

		if(!sig.verify(signature))
			throw new AuthenticationException("You are not authorized to log in");


		Calendar date = Calendar.getInstance();
		date.setTime(new Date());
		date.add(Calendar.MINUTE, SESSIONTIME);
		Sessions.put(pubKey.toString(), date);
		sc.renewKey(Integer.toString(random.nextInt()), 16, "AES");
		storeKey(pubKey, sc.getSecretKey());

		return ac.wrapKey(pubKey, sc.getSecretKey());
	}

	@Override
	public byte[] register(PublicKey pubKey, String nonce, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, AuthenticationException, IllegalBlockSizeException {
		if(db.checkNonce(nonce, pubKey.toString())){
			throw new AuthenticationException("This message has already been received");
		}
		else{
			db.addNonce(pubKey.toString(), nonce);
		}	
		if(!verifySignature(pubKey,nonce,signature)){
			throw new AuthenticationException("You are not authorized to register");
		}

		if(db.checkClient(pubKey.toString())) {
			throw new AuthenticationException("This public key is already registered");
		}
		db.AddClient(pubKey.toString(), 100);

		Calendar date = Calendar.getInstance();
		date.setTime(new Date());
		date.add(Calendar.MINUTE, SESSIONTIME);
		Sessions.put(pubKey.toString(), date);
		sc.renewKey(Integer.toString(random.nextInt()), 16, "AES");
		storeKey(pubKey, sc.getSecretKey());

		return ac.wrapKey(pubKey, sc.getSecretKey());
	}

	@Override
	public byte[][] checkAccount(PublicKey pubKey, String nonce,  byte[] hmac) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, Exception {
		if(db.checkNonce(nonce, pubKey.toString())){
			throw new AuthenticationException("This message has already been received");
		}
		else{
			db.addNonce(pubKey.toString(), nonce);
		}	
		String serverReply = "";
		String concatenation = pubKey + nonce;

		if(!verifySession(pubKey))
			throw new AuthenticationException("Not in Session");

		try {
			if(!macVerifier.verifyHMAC(hmac, ks.getKey(pubKey.toString(), PASSWORD), concatenation))
				throw new AuthenticationException("Hmac is wrong");
		} catch (Exception e) {
			throw new AuthenticationException("Could not authenticate");
		}


		int balance = db.getBalance(pubKey.toString()); //returns int
		serverReply = serverReply + "Your balance is:\n "+ Integer.toString(balance);
		List<String> result = db.getIncomingPendingTransfers(pubKey.toString()); //returns a list of all pending request

		byte[][] reply = new byte[2][];
		reply[0] = serverReply.getBytes("UTF-8");
		reply[1] = macVerifier.createHmac(serverReply, ks.getKey(pubKey.toString(), PASSWORD));

		if(result.isEmpty()){
			return reply;
		}
		else{
			serverReply = serverReply + "\nYou have the following pending:";
			for(String str: result){
				serverReply = serverReply + "\n" +str;
			}
			reply[0] = serverReply.getBytes("UTF-8");
			reply[1] = macVerifier.createHmac(serverReply, ks.getKey(pubKey.toString(), PASSWORD));
			return reply;
		}
	}

	@Override
	public byte[][] sendAmount(PublicKey src, String dst, int amount, String nonce, byte[] signature, byte[] hmac) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, Exception {
		if(db.checkNonce(nonce, src.toString())){
			throw new AuthenticationException("This message has already been received");
		}
		else{
			db.addNonce(src.toString(), nonce);
		}	

		if(!verifySession(src))
			throw new AuthenticationException("Not in Session");

		String concatenation = src+dst+amount+nonce;

		if(!macVerifier.verifyHMAC(hmac, ks.getKey(src.toString(), PASSWORD), concatenation))
			throw new AuthenticationException("Hmac is wrong");


		Signature sig = Signature.getInstance("SHA1withRSA"); //verifies the signature of the nonce
		sig.initVerify(src);
		sig.update( (dst+amount).getBytes() );

		if(!sig.verify(signature))
			throw new AuthenticationException("Signature is incorrect");

		
		
		int newBalance = db.getBalance(src.toString()) - amount;
		if(newBalance < 0)
			throw new AuthenticationException("WARNING: Insuficient balance!");

		db.CreatePendingLedgerAndUpdateBalance(src.toString(), dst, amount, newBalance, signature.toString());
		//made a new one with both create ledger and update balance in order to ensure that they both happen or none of them happen

		String serverReply = "Sucess, transaction is now pending";

		byte[][] reply = new byte[2][];
		reply[0] = serverReply.getBytes("UTF-8");
		reply[1] = macVerifier.createHmac(serverReply, ks.getKey(src.toString(), PASSWORD));

		return reply;
	}

	@Override
	public byte[][] receiveAmount(PublicKey pubKey, int id, String nonce, byte[] hmac) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, Exception {
		if(db.checkNonce(nonce, pubKey.toString())){
			throw new AuthenticationException("This message has already been received");
		}
		else{
			db.addNonce(pubKey.toString(), nonce);
		}	
		if(!verifySession(pubKey))
			throw new AuthenticationException("Not in Session");

		String concatenation = nonce + pubKey + id;
		try {
			if(!macVerifier.verifyHMAC(hmac, ks.getKey(pubKey.toString(), PASSWORD), concatenation))
				throw new AuthenticationException("Hmac is wrong");
		} catch (Exception e) {
			throw new AuthenticationException("Could not authenticate");
		}

		db.AcceptTransactionAndUpdateBalance(pubKey.toString(), id);

		String serverReply = "Check your new balance";

		byte[][] reply = new byte[2][];
		reply[0] = serverReply.getBytes("UTF-8");
		reply[1] = macVerifier.createHmac(serverReply, ks.getKey(pubKey.toString(), PASSWORD));

		return reply;
	}	

	@Override
	public String audit(PublicKey pubKey,String audited, String nonce, byte[] signature) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, Exception {
		if(db.checkNonce(nonce, pubKey.toString())){
			throw new AuthenticationException("This message has already been received");
		}
		else{
			db.addNonce(pubKey.toString(), nonce);
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
