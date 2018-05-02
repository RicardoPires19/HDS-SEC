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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.sasl.AuthenticationException;
import javax.swing.JLabel;
import javax.swing.JOptionPane;

import common.AsymmetricCryptography;
import common.verifyMac;

public class ClientLibrary {
	private AsymmetricCryptography ac;
	private static PublicKey pubKey;
	private static PrivateKey priKey;
	private HashMap<Client, SecretKey> Servers = new HashMap<Client, SecretKey>(30);
	private final verifyMac mV = new verifyMac();
	private int rid = 0, seq = 0, wts = 0, acks = 0;
	private boolean reading = false;
	private ArrayList<byte[]> readlist = new ArrayList<byte[]>(50);
	private byte[] readval = null;


	private ClientLibrary() throws NoSuchAlgorithmException, NoSuchPaddingException {
		ac = new AsymmetricCryptography();
	}

	protected HashMap<Client, SecretKey> getRMIDemo() {
		return Servers;
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, CertificateException, IOException, NoSuchProviderException, NotBoundException, InvalidKeyException, SignatureException, InvalidKeySpecException, NumberFormatException, SQLException{
		ClientLibrary cl = new ClientLibrary();
		int n = Integer.parseInt(args[1]);
		if (args.length == 2) {
			for (int i = 0; i < n; i++) {
				String url = new String("rmi://localhost/Server" + i);
				cl.getRMIDemo().put( (Client)Naming.lookup(url), null );
			}

			try {
				cl.startMenu();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		else {
			System.err.println("Usage: RMIDemoClient <server>");
		}
	}

	public void startMenu() throws Exception{
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

	public void mainMenu(String serverReply) throws NumberFormatException, RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnsupportedEncodingException, SQLException{

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
			for (Client c : Servers.keySet()) {
				String nonce = c.createNonce(pubKey);
				c.logout(pubKey, nonce, createSignature(nonce,priKey));
			}
			startMenu();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return;

		default:goodbyeMenu();
		return;

		}
	}

	public void loginMenu() throws Exception{
		byte[] serverReply;
		String res = JOptionPane.showInputDialog(null, "Input Username:", "Register", 
				JOptionPane.OK_CANCEL_OPTION,null, null, JOptionPane.PLAIN_MESSAGE).toString();

		if(res!=null){
			createOrReadKeys(res);
			try {
				int i = 0;
				for (Client c : Servers.keySet()) {
					String nonce = c.createNonce(pubKey);
					serverReply = c.login(pubKey, nonce, createSignature(nonce,priKey));	
					if(serverReply != null){
						Servers.put(c, (SecretKey) ac.unwrapKey(priKey, serverReply, "AES") );  // Type Cast is acceptable since a key of type SecretKey is expected
						i++;
					}
				}
				if(i == 0){
					loginMenu();
					return;
				}
				mainMenu("Login Sucessful");
			} catch (AuthenticationException e) {
				System.out.println("Authentication Failure");
			}
		}
		else{
			startMenu();
		}

	}

	public void registerMenu() throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, NumberFormatException, UnsupportedEncodingException, SQLException, IllegalBlockSizeException{

		byte[] serverReply;

		String res = JOptionPane.showInputDialog(null, "Select your username:", "Register", 
				JOptionPane.OK_CANCEL_OPTION,
				null, null, JOptionPane.PLAIN_MESSAGE).toString();

		if(res!=null){
			createOrReadKeys(res);
			try {
				int i = 0;
				for (Client c : Servers.keySet()) {
					String nonce = c.createNonce(pubKey);
					serverReply = c.register(pubKey, nonce, createSignature(nonce,priKey));	
					if(serverReply != null){
						Servers.put(c, (SecretKey) ac.unwrapKey(priKey, serverReply, "AES") );  // Type Cast is acceptable since a key of type SecretKey is expected
						i++;
					}
				}
				if(i == 0){
					registerMenu();
					System.out.println("Registration faleid on all servers.");
					return;
				}

				mainMenu("Registration Sucessful");
			} catch (AuthenticationException e) {
				System.out.println("Authentication Failure");
			}
		}
		else{
			goodbyeMenu();
		}
	}



	public void checkAccountMenu() throws RemoteException, NumberFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnsupportedEncodingException, SQLException{
		byte[][] serverReply, replies = new byte[Servers.size() + 1][];
		this.reading = true;
		try {
			int i = 0;
			for (Client c: Servers.keySet()) {
				String nonce = c.createNonce(pubKey);
				String concatenation = pubKey + nonce;
				serverReply = c.checkAccount(pubKey, nonce, mV.createHmac(concatenation, Servers.get(c)), rid, seq);

				int srid = Integer.parseInt(new String(serverReply[2]));
				int sseq = Integer.parseInt(new String(serverReply[3]));

				if(mV.verifyHMAC(serverReply[1], Servers.get(c), new String(serverReply[0], "UTF-8"))
						&& srid == rid && sseq == (seq+1) ) {
					replies[i] = serverReply[0];
				}
				i++;
			}
			byte[] decision = quorum(replies);

			int res = JOptionPane.showConfirmDialog(null, new String(decision, "UTF-8"), "Account Info", 
					JOptionPane.CANCEL_OPTION,
					JOptionPane.INFORMATION_MESSAGE);
			
			this.reading = false;
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

	public void sendAmountMenu() throws NumberFormatException, RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnsupportedEncodingException, SQLException{
		byte[][] serverReply = null, replies = new byte[Servers.size() + 1][];
		Optional<Client> any = Servers.keySet().stream().findAny();
		List<String> dest_choices = any.get().getPublicKeys(pubKey);
		Object[] obj = dest_choices.toArray();

		JLabel label_destination = new JLabel("To whom:");

		String choice = JOptionPane.showInputDialog(null, label_destination,
				"SendAmount", JOptionPane.QUESTION_MESSAGE, null, obj, obj[0]).toString();

		System.out.println(choice);

		JLabel label_amount = new JLabel("How much:");

		Object res = JOptionPane.showInputDialog(null,label_amount,JOptionPane.QUESTION_MESSAGE);

		if(res != null){

			try {
				int i = 0;
				for(Client c : Servers.keySet()) {
					String nonce = c.createNonce(pubKey);
					String concatenation = pubKey+choice+Integer.parseInt(res.toString())+nonce;

					Signature sig = Signature.getInstance("SHA1withRSA"); //verifies the signature of the nonce
					sig.initVerify(pubKey);
					sig.update( (pubKey+choice+res.toString()).getBytes() );

					serverReply = c.sendAmount(pubKey, 
							choice, 
							Integer.parseInt(res.toString()), 
							nonce, 
							createSignature(choice+res.toString(), priKey), 
							mV.createHmac(concatenation, Servers.get(c)),
							wts, seq);

					int swts = Integer.parseInt(new String(serverReply[2]));
					int sseq = Integer.parseInt(new String(serverReply[3]));
					if(mV.verifyHMAC(serverReply[1], Servers.get(c), new String(serverReply[0], "UTF-8"))
							&& swts == (wts+1) && sseq == (seq+1) ) {
						replies[i] = serverReply[0];
						acks++;
					}
					i++;
				}
				
				if(acks < (Servers.size() / 2) )
					throw new AuthenticationException("Not enough writes: " + acks);
				
				this.acks = 0;
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

	public void receiveAmountMenu() throws NumberFormatException, RemoteException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnsupportedEncodingException, SQLException{
		byte[][] serverReply = null, replies = new byte[Servers.size() + 1][];
		Optional<Client> any = Servers.keySet().stream().findAny();
		List<String> dest_choices = any.get().getPublicKeys(pubKey);
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
				int result_id = Integer.parseInt(choice.substring(3, choice.indexOf("Sender:")).trim());
				try {
					int i = 0;
					for(Client c : Servers.keySet()) {
						String nonce = c.createNonce(pubKey);
						String concatenation = nonce + pubKey + result_id;
						serverReply = c.receiveAmount(pubKey, result_id, nonce, mV.createHmac(concatenation, Servers.get(c)), wts, seq);

						int swts = Integer.parseInt(new String(serverReply[2]));
						int sseq = Integer.parseInt(new String(serverReply[3]));
						if(mV.verifyHMAC(serverReply[1], Servers.get(c), new String(serverReply[0], "UTF-8"))
								&& swts == (wts+1) && sseq == (seq+1) ) {
							replies[i] = serverReply[0];
							acks++;
						}
						i++;
					}

					if(acks < (Servers.size() / 2) )
						throw new AuthenticationException("Not enough writes: " + acks);

					this.acks = 0;
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

	public void auditMenu() throws RemoteException, NumberFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnsupportedEncodingException, SQLException{
		String[] serverReply;
		byte[][] replies = new byte[Servers.size() + 1][];
		Optional<Client> any = Servers.keySet().stream().findAny();
		List<String> dest_choices = any.get().getPublicKeys(pubKey);
		// Needs changing

		Object[] obj = dest_choices.toArray();

		JLabel label_destination = new JLabel("Audit whom:");

		this.reading = true;
		String choice = JOptionPane.showInputDialog(null, label_destination,
				"SendAmount", JOptionPane.QUESTION_MESSAGE, null, obj, obj[0]).toString();

		if(choice != null){
			try {
				int i = 0;
				for (Client c: Servers.keySet()) {
					String nonce = c.createNonce(pubKey);
					serverReply = c.audit(pubKey, choice, nonce, rid, seq);

					int srid = Integer.parseInt(serverReply[1]);
					int sseq = Integer.parseInt(serverReply[2]);
					if(srid == rid && sseq == (seq+1) ) {
						replies[i] = serverReply[0].getBytes();
						return;
					}
					i++;
				}
				byte[] decision = quorum(replies);
				
				this.reading = false;
				JOptionPane.showConfirmDialog(null, new String(decision),
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
		JOptionPane.showConfirmDialog(null, "Thank you, " + pubKey.toString()+" please come again!",
				"Goodbye",
				JOptionPane.PLAIN_MESSAGE,
				JOptionPane.QUESTION_MESSAGE);
		return;
	}

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

	private byte[] quorum(byte[][] serverReply) {
		HashMap<byte[], Integer> replies = new HashMap<byte[], Integer>(serverReply.length);

		for (byte[] bs : serverReply) {
			replies.merge(bs, 1, Integer::sum);
		}

		Map.Entry<byte[], Integer> max = null;
		for (Map.Entry<byte[], Integer> entry : replies.entrySet()) {
			if(max == null || entry.getValue() > max.getValue())
				max = entry;
		}

		return max.getKey();
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
