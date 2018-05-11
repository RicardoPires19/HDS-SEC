package main;

import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.HashMap;

import common.AsymmetricKeyGenerator;

public class SafeServer extends UnicastRemoteObject implements SafeVerifier {
	private static final long serialVersionUID = 2984153093736120567L;
	private final int nServers;
	private ArrayList<String> inputs;
	private AsymmetricKeyGenerator akg;


	public SafeServer(int nServers) throws RemoteException{
		this.nServers = nServers;
		inputs = new ArrayList<String>(nServers);
		try {
			akg = new AsymmetricKeyGenerator(512, "SafeKey");
			akg.createKeyPair();
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void sendInput(String input, PublicKey pubKey, byte[] signature) throws RemoteException {
		try {
			if(verifySignature(pubKey, input, signature))
				inputs.add(input);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			e.printStackTrace();
		}
	}

	@Override
	public byte[][] verifyInput() throws RemoteException {
		int f = this.nServers - inputs.size(), max = 0;
		HashMap<String, Integer> inp = new HashMap<String, Integer>(this.nServers);

		for (String string : inputs) {
			if (inp.containsKey(string)) {
				int k = inp.get(string);
				inp.put(string, ++k);
				if(k>max)
					max = k;
			}
			else
				inp.put(string, 0);
		}

		if( max < 2*f+1 ) {
			return null;
		}
		else {
			byte[][] reply = new byte[2][];
			reply[0] = createSignature("ack");
			reply[1] = akg.getPublicKey().getEncoded();
			return reply;
		}

	}

	private byte[] createSignature(String input) {  //input can be both a nonce or a HMAC
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


	private boolean verifySignature(PublicKey pubKey, String nonce, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{

		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initVerify(pubKey);
		sig.update(nonce.getBytes());
		if(!sig.verify(signature))
			return false;

		return true;

	}
}
