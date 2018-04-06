
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.sql.SQLException;
import java.util.*;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.sasl.AuthenticationException;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;

import AsymetricEncription.AsymmetricCryptography;
import AsymetricEncription.AsymmetricKeyGenerator;

@SuppressWarnings("unused")
public class testRMIClient {
	private static char[] PASSWORD = {'a','b'};
	private static AsymmetricCryptography ac;
	private static AsymmetricKeyGenerator akg;
	private static SymetricKeyGenerator sc;
	private static MysqlCon db;
	private static KeyStore ks;
	private static KeyFactory kf;
	public static PublicKey pubKey;
	public static byte[] pubKeyBytes;
	public static PrivateKey priKey;
	public static Client RMIDemo;
	public static SecretKey secretKey;
	private static final verifyMac mV = new verifyMac();
	

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, CertificateException, IOException, NoSuchProviderException, NotBoundException, InvalidKeyException, SignatureException, InvalidKeySpecException, NumberFormatException, SQLException{
		if (args.length == 1) {
			String url = new String("rmi://"+args[0]+"/RMIDemo");

			try {
				RMIDemo = (Client)Naming.lookup(url);

				akg = new AsymmetricKeyGenerator(512, "ServerKey");
				akg.createKeyPair();
				priKey = akg.getPrivateKey();
				pubKey = akg.getPublicKey();
				pubKeyBytes = pubKey.getEncoded();

				sc = new SymetricKeyGenerator();
				ac = new AsymmetricCryptography();

				ks = KeyStore.getInstance("JKS");

			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				e.printStackTrace();
			}

			registerMenu();
		}else {
			System.err.println("Usage: RMIDemoClient <server>");
		}
	}

	public static void registerMenu() throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, NumberFormatException, UnsupportedEncodingException, SQLException{
		JLabel label_key = new JLabel("Dgive Key:");
		JTextField key = new JTextField();

		SecretKey serverReply;

		Object[] array = {label_key,  key};

		int res = JOptionPane.showConfirmDialog(null, array, "Register", 
				JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.PLAIN_MESSAGE);

		if (res == JOptionPane.OK_OPTION) {
			String nonce = RMIDemo.createNonce(pubKey);
			System.out.println(createSignature(nonce).toString());
			try {
				serverReply = RMIDemo.register(pubKey,nonce, createSignature(nonce));
				if(serverReply == null){
					mainMenu("An Error ocurred. Registration Failed.");
					System.out.println("serverReply: " + serverReply);
					return;
				}

				secretKey = serverReply;
				mainMenu("Registration Sucessful");
			} catch (AuthenticationException e) {
				System.out.println("Authentication Failure");
			}
		}
		else{
			goodbyeMenu();
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

		case 4: registerMenu();
		return;

		default:goodbyeMenu();
		return;

		}
	}

	public static void checkAccountMenu() throws RemoteException, NumberFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnsupportedEncodingException, SQLException{
		String nonce = RMIDemo.createNonce(pubKey);
		String serverReply;

		try {
			//			serverReply = RMIDemo.checkAccount(pubKey,nonce, createSignature(nonce),createHash(pubKey.toString())).toString();
			String concatenation = pubKey + nonce;
			serverReply = RMIDemo.checkAccount(pubKey, nonce, mV.createHmac(concatenation, secretKey));
			int res = JOptionPane.showConfirmDialog(null, serverReply.toString(), "Account Info", 
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

			String serverReply;
			try {
				//				serverReply = RMIDemo.sendAmount(pubKey, pubKey, Integer.parseInt(res.toString()), nonce, createSignature(nonce));
				String concatenation = pubKey+choice+Integer.parseInt(res.toString())+nonce;
				serverReply = RMIDemo.sendAmount(pubKey, choice, Integer.parseInt(res.toString()), nonce, mV.createHmac(concatenation, secretKey));
				JOptionPane.showConfirmDialog(null, serverReply, "Account Info", 
						JOptionPane.CANCEL_OPTION,
						JOptionPane.INFORMATION_MESSAGE); // Initial choice);

				mainMenu("While you wait for " +choice+" to accept, what you wanna do next?");
			} catch (Exception e) {
				// TODO Auto-generated catch block
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
				String serverReply;
				String concatenation = nonce + pubKey + result_id;
				try {
					//					serverReply = RMIDemo.receiveAmount(pubKey,result_id,nonce,createSignature(nonce));
					serverReply = RMIDemo.receiveAmount(pubKey, result_id, nonce, mV.createHmac(concatenation, secretKey));
					JOptionPane.showConfirmDialog(null, serverReply, "Account Info", 
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
			String serverReply = RMIDemo.audit(pubKey,choice.toString(),nonce,createSignature(nonce));
			JOptionPane.showConfirmDialog(null, serverReply,
					"Auditing " + choice,
					JOptionPane.PLAIN_MESSAGE,
					JOptionPane.INFORMATION_MESSAGE);
			mainMenu("Whut u wanna do now?");
		}
		else{
			mainMenu("Whut u wanna do now?");
		}
	}

	public static void goodbyeMenu(){
		
		try {
			String nonce = RMIDemo.createNonce(pubKey);
			RMIDemo.logout(pubKey, nonce, createSignature(nonce));
		} catch (AuthenticationException | InvalidKeyException | NoSuchAlgorithmException | SignatureException | RemoteException e) {
			e.printStackTrace();
			return;
		}
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

	public static byte[] createSignature(String input) {  //input can be both a nonce or a HMAC
		byte[] data;
		try {
			data = input.getBytes("UTF8");
			Signature sig = Signature.getInstance("SHA1WithRSA");
			sig.initSign(priKey);
			sig.update(data);
			byte[] signatureBytes = sig.sign();
			return signatureBytes;
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
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
