
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
//import java.security.KeyStore;
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
import java.security.KeyStore.SecretKeyEntry;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.sql.SQLException;
import java.util.*;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;

import AsymetricEncription.AsymmetricCryptography;
import AsymetricEncription.AsymmetricKeyGenerator;
import AsymetricEncription.KeyStore;

@SuppressWarnings("unused")
public class RMIClient {
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
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, CertificateException, IOException, NoSuchProviderException, NotBoundException, InvalidKeyException, SignatureException, InvalidKeySpecException, NumberFormatException, SQLException{
		if (args.length == 1) {
			String url = new String("rmi://"+args[0]+"/RMIDemo");
			
			try {
				RMIDemo = (Client)Naming.lookup(url);
				try {
					pubKey = KeyStore.readPublicKey();
					priKey = KeyStore.readPrivateKey();
				} catch (Exception e) {
					try {
						KeyStore.createKeyPair();
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
//				akg = new AsymmetricKeyGenerator(512, "ServerKey");
//				akg.createKeys();
//				priKey = akg.getPrivateKey();
//				pubKey = akg.getPublicKey();
//				pubKeyBytes = pubKey.getEncoded();
				
				sc = new SymetricKeyGenerator();
				ac = new AsymmetricCryptography();
				
				//ks = KeyStore.getInstance("JKS");

			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				e.printStackTrace();
			}
			
			registerMenu();
		}else {
			System.err.println("Usage: RMIDemoClient <server>");
		}
	}

	public static void registerMenu() throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, NumberFormatException, UnsupportedEncodingException, SQLException{
		
		Object[] options = {"START",
                "NVM BYE"};
		int res = JOptionPane.showOptionDialog(null,
			"Welcome to HDS Coin",
			"HDS Coin",
			JOptionPane.YES_NO_CANCEL_OPTION,
			JOptionPane.QUESTION_MESSAGE,
			null,
			options,
			options[0]);
		
		if (res == JOptionPane.OK_OPTION) {
			String nonce = RMIDemo.createNonce(pubKey);
			System.out.println(createSignature(nonce).toString());
			String serverReply = RMIDemo.register(pubKey,nonce, createSignature(nonce),createHash(pubKey.toString()));
			mainMenu(serverReply);
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
		String serverReply = RMIDemo.checkAccount(pubKey,nonce, createSignature(nonce),createHash(pubKey.toString()));
		int res = JOptionPane.showConfirmDialog(null, serverReply, "Account Info", 
		        JOptionPane.CANCEL_OPTION,
		        JOptionPane.INFORMATION_MESSAGE);
			if(res == JOptionPane.OK_OPTION){
				mainMenu("Not doing so well uh? What you wanna do now ");
				return;
			}
			else{
				goodbyeMenu();
				return;
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
			String serverReply = RMIDemo.sendAmount(pubKey, pubKey, Integer.parseInt(res.toString()), nonce, createSignature(nonce),createHash(pubKey.toString()));
			JOptionPane.showConfirmDialog(null, serverReply, "Account Info", 
			        JOptionPane.CANCEL_OPTION,
			        JOptionPane.INFORMATION_MESSAGE); // Initial choice);
			
			mainMenu("While you wait for " +choice+" to accept, what you wanna do next?");
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
				String serverReply = RMIDemo.receiveAmount(pubKey,result_id,nonce,createSignature(nonce),createHash(pubKey.toString()));
				JOptionPane.showConfirmDialog(null, serverReply, "Account Info", 
				        JOptionPane.CANCEL_OPTION,
				        JOptionPane.INFORMATION_MESSAGE);
				mainMenu("Nice, you almost rich man");
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
			String serverReply = RMIDemo.audit(pubKey,choice.toString(),nonce,createSignature(nonce),createHash(pubKey.toString()));
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
		JOptionPane.showConfirmDialog(null, "Thank you, " +pubKey.toString()+" please come again!",
			    "Goodbye",
			    JOptionPane.PLAIN_MESSAGE,
			    JOptionPane.QUESTION_MESSAGE);
		return;
	}
	
	//SIGNATURE PROVES THAT THE MENSAGE WAS SENT BY THE USER
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
	
	
	// HASH IS USED TO PROVE THE TEXT HASNT BEEN MODIFIED
	public static byte[] createHash(String args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
	    MessageDigest md = MessageDigest.getInstance("MD5");
	    md.update(args.getBytes());
	    return md.digest();
	}
	
}
