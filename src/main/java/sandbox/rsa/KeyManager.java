package sandbox.rsa;


import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


public class KeyManager {
	private Base64.Encoder encoder = Base64.getEncoder();
	
	private KeyPair keyPair;
	
	public void generate() {
		tryGenerate();
	}

	private void tryGenerate() {
		try {
			doGenerate();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void doGenerate() throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		keyPair = kpg.generateKeyPair();
	}
	
	public KeyPair getKeyPair() {
		return keyPair;
	}
	
	public void saveToFile(String outFile) {
		
		try {
			doSaveToFile(outFile);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void doSaveToFile(String outFile) throws FileNotFoundException, IOException {
		if (keyPair.getPrivate() != null) {
			try(FileOutputStream out = new FileOutputStream(outFile + ".key")) {
				out.write(keyPair.getPrivate().getEncoded());
			}
		}
		if (keyPair.getPublic() != null) {
			try(FileOutputStream out = new FileOutputStream(outFile + ".pub")) {
				out.write(keyPair.getPublic().getEncoded());
			}
		}
	}
	
	public void loadFromFile(String infile) {
		tryLoadFromFile(infile);
	}

	private void tryLoadFromFile(String infile)  {
		try {
			PrivateKey pk = loadPrivateKeyFromFile(infile + ".key");
			PublicKey pub = loadPublicKeyFromFile(infile + ".pub");
			keyPair = new KeyPair(pub, pk);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private PublicKey loadPublicKeyFromFile(String infile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] bytes = readAllBytesFrom(infile);
		if (bytes == null) return null;
		PublicKey pub = generatePublicKey(bytes);
		return pub;
	}

	private PublicKey generatePublicKey(byte[] bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pub = kf.generatePublic(ks);
		return pub;
	}

	private PrivateKey loadPrivateKeyFromFile(String infile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] bytes = readAllBytesFrom(infile);
		if (bytes == null) return null;
		PrivateKey pvt = generatePrivateKey(bytes);
		return pvt;
	}

	private PrivateKey generatePrivateKey(byte[] bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey pvt = kf.generatePrivate(ks);
		return pvt;
	}

	private byte[] readAllBytesFrom(String infile) throws IOException {
		Path path = Paths.get(infile);
		if (!path.toFile().exists()) return null;
		byte[] bytes = Files.readAllBytes(path);
		return bytes;
	}

	public RSAPublicKey getRSAPublicKey() {
		return (RSAPublicKey) getKeyPair().getPublic();
	}

	public RSAPrivateKey getRSAPrivateKey() {
		return (RSAPrivateKey) getKeyPair().getPrivate();
	}

	public void createKeyPairFrom(BigInteger modulus, BigInteger pubexp, BigInteger prvexp) {
		// Create private and public key specs
		RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, pubexp);
		RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(modulus, prvexp);
		KeyFactory factory;
		try {
			factory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = factory.generatePublic(publicSpec);
			PrivateKey privateKey = factory.generatePrivate(privateSpec);
			KeyPair kp = new KeyPair(publicKey, privateKey);
			this.keyPair = kp;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void saveToPemFile(String filename) {
		try {
			doSaveToPemFile(filename);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	private void doSaveToPemFile(String filename) throws IOException {
		
		PrivateKey pvt = getKeyPair().getPrivate();
		if (pvt != null) {
			try (Writer out = new FileWriter(filename + ".key")) {
				out.write("-----BEGIN RSA PRIVATE KEY-----\n");
				out.write(encoder.encodeToString(pvt.getEncoded()));
				out.write("\n-----END RSA PRIVATE KEY-----\n");
			}
		}
		
		PublicKey pub = getKeyPair().getPublic();
		if (pub != null) {
			try (Writer out = new FileWriter(filename + ".pub")) {
				out.write("-----BEGIN RSA PUBLIC KEY-----\n");
				out.write(encoder.encodeToString(pub.getEncoded()));
				out.write("\n-----END RSA PUBLIC KEY-----\n");
			}
		}
	}
	
	
}