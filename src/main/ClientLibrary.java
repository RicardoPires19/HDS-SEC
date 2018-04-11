package main;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
import java.util.List;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.sasl.AuthenticationException;
import javax.swing.JLabel;
import javax.swing.JOptionPane;

import common.AsymmetricCryptography;
import common.verifyMac;

public class ClientLibrary {
	private static AsymmetricCryptography ac;
	private static PublicKey pubKey;
	private static PrivateKey priKey;
	private static SecretKey secretKey;
	private static Client RMIDemo;
	private static final verifyMac mV = new verifyMac();


	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, CertificateException, IOException, NoSuchProviderException, NotBoundException, InvalidKeyException, SignatureException, InvalidKeySpecException, NumberFormatException, SQLException{
		ac = new AsymmetricCryptography();
		if (args.length == 1) {
			String url = new String("rmi://"+args[0]+"/ServerLibrary");
			ClientLibrary.RMIDemo = (Client)Naming.lookup(url);
			try {
				startMenu();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		else {
			System.err.println("Usage: RMIDemoClient <server>");
		}
	}

	public static void startMenu() throws Exception{
		Object[] options = {"Login",
				"Register","NVM, BYE!"};

		int res = JOptionPane.showOptionDialog(null,
				"Welcome to HDS Coin",
				"HDS Coin",
				JOptionPane.YES_NO_CANCEL_OPTION,
				JOptionPane.QUESTION_MESSAGE,
				null,
				options,
				options[0]);

		if(res ==0){
			loginMenu();
		}
		if(res == 1){
			registerMenu();
		}
	}
	
	public static void mainMenu(String serverReply) throws NumberFormatException, RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnsupportedEncodingException, SQLException{

		Object[] options = {"Check Account", "Send Amount","Receive Amount", "Audit", "Logout"};
		int res = JOptionPane.showOptionDialog(null, serverReply,
				"HDS Coin",
				JOptionPane.YES_NO_OPTION,
				JOptionPane.QUESTION_MESSAGE,
				null,     //do not use a custom Icon
				options,  //the titles of buttons
				options[0]);
		switch(res){
		case 0: checkAccountMenu();
		return;

		case 1:	sendAmountMenu();
		return;

		case 2: receiveAmountMenu();
		return;

		case 3: auditMenu();
		return;

		case 4: try {
			String nonce = RMIDemo.createNonce(pubKey);
			RMIDemo.logout(pubKey, nonce, createSignature(nonce,priKey));
			startMenu();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return;

		default:goodbyeMenu();
		return;

		}
	}

	public static void loginMenu() throws Exception{
		byte[] serverReply;
		String res = JOptionPane.showInputDialog(null, "Input Username:", "Register", 
				JOptionPane.OK_CANCEL_OPTION,null, null, JOptionPane.PLAIN_MESSAGE).toString();

		if(res!=null){
			createOrReadKeys(res);
			String nonce = RMIDemo.createNonce(pubKey);
			try {
				serverReply = RMIDemo.login(pubKey,nonce, createSignature(nonce,priKey));	
				if(serverReply == null){
					loginMenu();
					return;
				}
				secretKey = (SecretKey) ac.unwrapKey(priKey, serverReply, "AES");  // Type Cast is acceptable since a key of type SecretKey is expected
				mainMenu("Login Sucessful");

			} catch (AuthenticationException e) {
				System.out.println("Authentication Failure");
			}
		}
		else{
			startMenu();
		}

	}

	public static void registerMenu() throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, NumberFormatException, UnsupportedEncodingException, SQLException, IllegalBlockSizeException{

		byte[] serverReply;

		String res = JOptionPane.showInputDialog(null, "Select your username:", "Register", 
				JOptionPane.OK_CANCEL_OPTION,
				null, null, JOptionPane.PLAIN_MESSAGE).toString();

		if(res!=null){
			createOrReadKeys(res);
			String nonce = RMIDemo.createNonce(pubKey);
			try {
				serverReply = RMIDemo.register(pubKey,nonce, createSignature(nonce,priKey));
				if(serverReply == null){
					registerMenu();
					System.out.println("serverReply: " + serverReply);

					return;
				}
				secretKey = (SecretKey) ac.unwrapKey(priKey, serverReply, "AES");  // Type Cast is acceptable since a key of type SecretKey is expected
				mainMenu("Registration Sucessful");
			} catch (AuthenticationException e) {
				System.out.println("Authentication Failure");
			}
		}
		else{
			goodbyeMenu();
		}
	}

	

	public static void checkAccountMenu() throws RemoteException, NumberFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnsupportedEncodingException, SQLException{
		String nonce = RMIDemo.createNonce(pubKey);
		byte[][] serverReply;

		try {
			String concatenation = pubKey + nonce;
			serverReply = RMIDemo.checkAccount(pubKey, nonce, mV.createHmac(concatenation, secretKey));
			
			
			if(!mV.verifyHMAC(serverReply[1], secretKey, new String(serverReply[0], "UTF-8"))) {
				goodbyeMenu();
				return;
			}
			int res = JOptionPane.showConfirmDialog(null, new String(serverReply[0], "UTF-8"), "Account Info", 
					JOptionPane.CANCEL_OPTION,
					JOptionPane.INFORMATION_MESSAGE);
			if(res == JOptionPane.OK_OPTION){
				mainMenu("Not doing so well uh? What you wanna do now?");
				return;
			}
			else{
				goodbyeMenu();
				return;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public static void sendAmountMenu() throws NumberFormatException, RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnsupportedEncodingException, SQLException{

		List<String> dest_choices = RMIDemo.getPublicKeys(pubKey);
		Object[] obj = dest_choices.toArray();

		JLabel label_destination = new JLabel("To whom:");

		String choice = JOptionPane.showInputDialog(null, label_destination,
				"SendAmount", JOptionPane.QUESTION_MESSAGE, null, obj, obj[0]).toString();

		System.out.println(choice);

		JLabel label_amount = new JLabel("How much:");


		Object res = JOptionPane.showInputDialog(null,label_amount,JOptionPane.QUESTION_MESSAGE);

		if(res != null){
			String nonce = RMIDemo.createNonce(pubKey);

			byte[][] serverReply;
			try {
				String concatenation = pubKey+choice+Integer.parseInt(res.toString())+nonce;
				
				serverReply = RMIDemo.sendAmount(pubKey, choice, Integer.parseInt(res.toString()), nonce, mV.createHmac(concatenation, secretKey));
				
				if(!mV.verifyHMAC(serverReply[1], secretKey, new String(serverReply[0], "UTF-8"))) {
					goodbyeMenu();
					return;
				}
				
				JOptionPane.showConfirmDialog(null, new String(serverReply[0], "UTF-8"), "Account Info", 
						JOptionPane.CANCEL_OPTION,
						JOptionPane.INFORMATION_MESSAGE); // Initial choice);

				mainMenu("While you wait for " + choice + " to accept, what you wanna do next?");
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		else{
			mainMenu("Whats up? Don't know who to send money to?");
			return;
		}
	}

	public static void receiveAmountMenu() throws NumberFormatException, RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnsupportedEncodingException, SQLException{

		List<String> dest_choices = RMIDemo.getPendingList(pubKey);
		Object[] obj = dest_choices.toArray();

		if(obj.length == 0){
			JOptionPane.showConfirmDialog(null, "No Pending Transactions",
					"Receive Amount",
					JOptionPane.PLAIN_MESSAGE,
					JOptionPane.WARNING_MESSAGE);
			mainMenu("No one wants to give you money!");
		}
		else{
			JLabel label_id = new JLabel("Pending List:");
			
			String choice = JOptionPane.showInputDialog(null, label_id,
					"SendAmount", JOptionPane.QUESTION_MESSAGE, null, obj, obj[0]).toString();

			System.out.println(choice);

			if (choice !=null){
				String nonce = RMIDemo.createNonce(pubKey);
				int result_id = Integer.parseInt(choice.substring(3, choice.indexOf("Sender:")).trim());
				byte[][] serverReply;
				try {
					//					serverReply = RMIDemo.receiveAmount(pubKey,result_id, nonce,createSignature(nonce));
					String concatenation = nonce + pubKey + result_id;
					serverReply = RMIDemo.receiveAmount(pubKey, result_id, nonce, mV.createHmac(concatenation, secretKey));
					
					if(!mV.verifyHMAC(serverReply[1], secretKey, new String(serverReply[0], "UTF-8"))) {
						goodbyeMenu();
						return;
					}
					
					
					JOptionPane.showConfirmDialog(null, new String(serverReply[0], "UTF-8"), "Account Info", 
							JOptionPane.CANCEL_OPTION,
							JOptionPane.INFORMATION_MESSAGE);
					mainMenu("Nice, you almost rich man");
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			else{
				mainMenu("Forgot id? Check Account");
			}
		}
		return;
	}

	public static void auditMenu() throws RemoteException, NumberFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnsupportedEncodingException, SQLException{


		List<String> dest_choices = RMIDemo.getPublicKeys(pubKey);
		Object[] obj = dest_choices.toArray();

		JLabel label_destination = new JLabel("Audit whom:");

		String choice = JOptionPane.showInputDialog(null, label_destination,
				"SendAmount", JOptionPane.QUESTION_MESSAGE, null, obj, obj[0]).toString();

		if(choice != null){
			String nonce = RMIDemo.createNonce(pubKey);
			byte[][] serverReply;
			try {
				serverReply = RMIDemo.audit(pubKey,choice.toString(),nonce,createSignature(nonce,priKey));

				if(!mV.verifyHMAC(serverReply[1], secretKey, new String(serverReply[0], "UTF-8"))) {
					goodbyeMenu();
					return;
				}
				
				
				JOptionPane.showConfirmDialog(null, new String(serverReply[0], "UTF-8"),
						"Auditing " + choice,
						JOptionPane.PLAIN_MESSAGE,
						JOptionPane.INFORMATION_MESSAGE);
				mainMenu("Whut u wanna do now?");
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		else{
			mainMenu("Whut u wanna do now?");
		}
	}

	public static void goodbyeMenu(){
		JOptionPane.showConfirmDialog(null, "Thank you, " +pubKey.toString()+" please come again!",
				"Goodbye",
				JOptionPane.PLAIN_MESSAGE,
				JOptionPane.QUESTION_MESSAGE);
		return;
	}

	//	public String createNonce() {
	//		SecureRandom nonce = new SecureRandom();
	//		String Nonce = nonce.toString();
	//		return Nonce;
	//	}

	public static void createOrReadKeys(String user){
		try {
			pubKey = common.KeyStorage.readPublicKey(user);
			priKey = common.KeyStorage.readPrivateKey(user);
		} catch (Exception e) {
			try {
				common.KeyStorage.createKeyPair(user, 512);
				pubKey = common.KeyStorage.readPublicKey(user);
				priKey = common.KeyStorage.readPrivateKey(user);
			} catch (Exception e1) {
				e1.printStackTrace();
			}
		}
	}
	
	public static byte[] createSignature(String input,PrivateKey privKey) {  //input can be both a nonce or a HMAC
		byte[] data;
		try {
			data = input.getBytes("UTF8");
			Signature sig = Signature.getInstance("SHA1WithRSA");
			sig.initSign(privKey);
			sig.update(data);
			byte[] signatureBytes = sig.sign();
			return signatureBytes;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;

	}

	public static byte[] createHash(String args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(args.getBytes());
		return md.digest();
	}

}
