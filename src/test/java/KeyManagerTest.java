import static org.junit.Assert.*;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.junit.Assert;
import org.junit.Test;


import sandbox.rsa.KeyManager;

public class KeyManagerTest {
	KeyManager km = new KeyManager();
	private String filename;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	@Test
	public void generate() {
		
		km.generate();
		PrivateKey pk = km.getKeyPair().getPrivate();
		PublicKey pub = km.getKeyPair().getPublic();
		
		assertTrue(pk instanceof RSAPrivateKey);
		assertTrue(pub instanceof RSAPublicKey);
	}
	
	@Test
	public void saveAndLoad() {
		km.generate();
		assignKeys();
		Path path;
		buildFileName();
		km.saveToFile(filename);
		path = Paths.get(System.getProperty("user.home"),"Documents","temp","chave.pub");
		assertTrue(path.toFile().exists());
		path = Paths.get(System.getProperty("user.home"),"Documents","temp","chave.key");
		assertTrue(path.toFile().exists());
		
		
		
		
	}

	private void assignKeys() {
		privateKey = km.getKeyPair().getPrivate();
		publicKey = km.getKeyPair().getPublic();
	}
	
	@Test
	public void testLoadWithoutPubKey() {
		buildFileName();
		Path path;
		km = new KeyManager();
		km.generate();
		km.saveToFile(filename);
		km = new KeyManager();
		path = Paths.get(System.getProperty("user.home"),"Documents","temp","chave.pub");
		path.toFile().delete();
		km.loadFromFile(filename);
		assertNull(km.getKeyPair().getPublic());
	}

	@Test
	public void testLoadWithoutFileKey() {
		buildFileName();
		km.generate();
		assignKeys();
		km.saveToFile(filename);
		Path path;
		km = new KeyManager();
		path = Paths.get(System.getProperty("user.home"),"Documents","temp","chave.key");
		path.toFile().delete();
		km.loadFromFile(filename);
		assertNull(km.getKeyPair().getPrivate());
		assertEquals(publicKey, km.getKeyPair().getPublic());
	}

	@Test
	public void testLoad() {
		buildFileName();
		km.generate();
		assignKeys();
		km.saveToFile(filename);
		km = new KeyManager();
		km.loadFromFile(filename);
		assertEquals(privateKey, km.getKeyPair().getPrivate());
		assertEquals(publicKey, km.getKeyPair().getPublic());
	}

	private void buildFileName() {
		Path path = Paths.get(System.getProperty("user.home"),"Documents","temp");
		File file = path.toFile();
		if (!file.exists()) {
			file.mkdirs();
		}
		filename = file.getAbsolutePath()+System.getProperty("file.separator")+"chave";
	}
	
	@Test
	public void getRSAPublicKey () {
		km.generate();
		assertNotNull(km.getRSAPublicKey());
	}
	
	@Test
	public void getRSAPrivateKey () {
		km.generate();
		assertNotNull(km.getRSAPrivateKey());
	}
	
	@Test
	public void testSaveToPemFile() {
		km.generate();
		assignKeys();
		buildFileName();
		km.saveToPemFile(filename);
		Path path = Paths.get(filename+".pub");
		assertTrue(path.toFile().exists());
		path = Paths.get(filename+".key");
		assertTrue(path.toFile().exists());
	}
	
	@Test 
	public void testLoadFromPemFile() {
		buildFileName();
		km.generate();
		assignKeys();
		km.saveToFile(filename);
		km = new KeyManager();
		km.loadFromFile(filename);
		assertEquals(privateKey, km.getKeyPair().getPrivate());
		assertEquals(publicKey, km.getKeyPair().getPublic());
	}
	
	@Test
	public void createKeyPairFromModulusAndExponent() {
		km.generate();
		assignKeys();
		RSAPublicKey rsapub = km.getRSAPublicKey();
		BigInteger modulus =  rsapub.getModulus();
		BigInteger pubexp = rsapub.getPublicExponent();
		RSAPrivateKey rsapk = km.getRSAPrivateKey();
		BigInteger prvexp = rsapk.getPrivateExponent();
		assertEquals(rsapub.getModulus(), rsapk.getModulus());
		km = new KeyManager();
		km.createKeyPairFrom(modulus, pubexp, prvexp);
		assertEquals(publicKey, km.getKeyPair().getPublic());
		RSAPrivateKey rpk = (RSAPrivateKey) privateKey;
		assertEquals(rpk.getPrivateExponent(), km.getRSAPrivateKey().getPrivateExponent());
		System.out.println("modulus " + modulus);
		System.out.println("public Exponent " + pubexp);
		System.out.println("private Exponent " + prvexp);
	}
	
}
