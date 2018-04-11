package tests;
import static org.junit.Assert.assertEquals;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import common.AsymmetricCryptography;
import common.AsymmetricKeyGenerator;
import common.KeyStorage;
import common.verifyMac;
import main.ClientLibrary;
import main.Server;
import main.ServerLibrary;

public class hdsTests {
	@Test
	public void test1startTests() throws Exception{
		Server.main(null);
	}
	
	@Test
	public void test2SimpleRegister() throws Exception {
		ServerLibrary cliAPI = new ServerLibrary();
		File f1 = new File("KeyStore\\publicKeysonic");
		File f2 = new File("KeyStore\\privateKeysonic");
		f1.delete();
		f2.delete();
		KeyStorage.createKeyPair("sonic", 512);
		PublicKey pubKey = KeyStorage.readPublicKey("sonic");
		PrivateKey priKey = KeyStorage.readPrivateKey("sonic");
		String nonce = cliAPI.createNonce(pubKey);
		byte[] serverReply = cliAPI.register(pubKey, nonce, ClientLibrary.createSignature(nonce,priKey));
		assertEquals("javax.crypto.spec.SecretKeySpec@16a40",serverReply.toString());
		
		f1 = new File("KeyStore\\publicKeyjammy");
		f2 = new File("KeyStore\\privateKeyjammy");
		f1.delete();
		f2.delete();
		KeyStorage.createKeyPair("jammy", 512);
		pubKey = KeyStorage.readPublicKey("jammy");
		priKey = KeyStorage.readPrivateKey("jammy");
		nonce = cliAPI.createNonce(pubKey);
		serverReply = cliAPI.register(pubKey, nonce, ClientLibrary.createSignature(nonce,priKey));
		assertEquals("javax.crypto.spec.SecretKeySpec@16bdc",serverReply.toString());
    }
	
	@Test
	public void test3SimpleLogin() throws Exception{
		ServerLibrary cliAPI = new ServerLibrary();
		File f1 = new File("KeyStore\\publicKeysonic");
		File f2 = new File("KeyStore\\privateKeysonic");
		f1.delete();
		f2.delete();
		KeyStorage.createKeyPair("sonic", 512);
		PublicKey pubKey = KeyStorage.readPublicKey("sonic");
		PrivateKey priKey = KeyStorage.readPrivateKey("sonic");
		String nonce = cliAPI.createNonce(pubKey);
		byte[] serverReply = cliAPI.register(pubKey, nonce, ClientLibrary.createSignature(nonce,priKey));
		assertEquals("javax.crypto.spec.SecretKeySpec@16a40",serverReply.toString());
		nonce = cliAPI.createNonce(pubKey);
		cliAPI.logout(pubKey, nonce, ClientLibrary.createSignature(nonce, priKey));
		nonce = cliAPI.createNonce(pubKey);
		serverReply = cliAPI.login(pubKey, nonce, ClientLibrary.createSignature(nonce,priKey));
		assertEquals("javax.crypto.spec.SecretKeySpec@16bdc",serverReply.toString());
	}
	
	@Test
	public void test4SimpleCheckAccount() throws Exception{
		ServerLibrary cliAPI = new ServerLibrary();
		KeyStorage.createKeyPair("ze", 512);
		PublicKey pubKey = KeyStorage.readPublicKey("ze");
		PrivateKey priKey = KeyStorage.readPrivateKey("ze");
		String nonce = cliAPI.createNonce(pubKey);
		byte[] secretkey = cliAPI.register(pubKey, nonce, ClientLibrary.createSignature(nonce,priKey));
		nonce = cliAPI.createNonce(pubKey);
		verifyMac mV = new verifyMac();
		String serverReply = cliAPI.checkAccount(pubKey, nonce, mV.createHmac(nonce, secretkey));
		assertEquals("Your balance is:\n 100",serverReply);
	}
	
	@Test
	public void test5SimpleSendAmount() throws Exception{
		ServerLibrary cliAPI = new ServerLibrary();
		PublicKey pubKey = KeyStorage.readPublicKey("sonic");
		PrivateKey priKey = KeyStorage.readPrivateKey("sonic");
		PrivateKey dstKey = KeyStorage.readPrivateKey("jammy");
		String nonce = cliAPI.createNonce(pubKey);
		byte[] secretkey = cliAPI.login(pubKey, nonce, ClientLibrary.createSignature(nonce,priKey));
		nonce = cliAPI.createNonce(pubKey);
		verifyMac mV = new verifyMac();
		String serverReply = cliAPI.sendAmount(pubKey, dstKey.toString(), 69, nonce, mV.createHmac(nonce, secretkey) );
		assertEquals("Sucess, transaction is now pending",serverReply);
	}
	
	@Test
	public void testSimpleReceiveAmount() throws Exception{
		ServerLibrary cliAPI = new ServerLibrary();
		PublicKey pubKey = KeyStorage.readPublicKey("jammy");
		PrivateKey priKey = KeyStorage.readPrivateKey("jammy");
		String nonce = cliAPI.createNonce(pubKey);
		byte[] secretkey = cliAPI.login(pubKey, nonce, ClientLibrary.createSignature(nonce,priKey));
		nonce = cliAPI.createNonce(pubKey);
		verifyMac mV = new verifyMac();
		String serverReply = cliAPI.receiveAmount(pubKey, 1, nonce, mV.createHmac(nonce, secretkey));
		assertEquals("TCHATCHING, check your new balance",serverReply);
	}
	
	@Test
	public void testXAudit() throws Exception{
		ServerLibrary cliAPI = new ServerLibrary();
		PublicKey dst = KeyStorage.readPublicKey("jammy");
		PublicKey pubKey = KeyStorage.readPublicKey("sonic");
		PrivateKey priKey = KeyStorage.readPrivateKey("sonic");
		String nonce = cliAPI.createNonce(pubKey);
		SecretKey secretkey = cliAPI.login(pubKey, nonce, ClientLibrary.createSignature(nonce,priKey));
		nonce = cliAPI.createNonce(pubKey);
		verifyMac mV = new verifyMac();
		String serverReply = cliAPI.audit(pubKey, dst.toString(), nonce, ClientLibrary.createSignature(nonce, priKey));
		assertEquals("",serverReply);
	}
}