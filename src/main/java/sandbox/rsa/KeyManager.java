package sandbox.rsa;


import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


public class KeyManager {
	Base64.Encoder encoder = Base64.getEncoder();
	
	KeyPair keyPair;
	
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
		try(FileOutputStream out = new FileOutputStream(outFile + ".key")) {
			out.write(keyPair.getPrivate().getEncoded());
		}

		try(FileOutputStream out = new FileOutputStream(outFile + ".pub")) {
			out.write(keyPair.getPublic().getEncoded());
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
		Path path = Paths.get(infile);
		byte[] bytes = Files.readAllBytes(path);

		/* Generate public key. */
		X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pub = kf.generatePublic(ks);
		return pub;
	}

	private PrivateKey loadPrivateKeyFromFile(String infile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		/* Read all bytes from the private key file */
		Path path = Paths.get(infile);
		byte[] bytes = Files.readAllBytes(path);

		/* Generate private key. */
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey pvt = kf.generatePrivate(ks);
		return pvt;
	}
	
	
}
