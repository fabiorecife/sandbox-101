package sandbox.rsa;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;


public class SharePrivateKeyMain {

	public static void main(String[] args) {
		System.out.println("start: " + LocalDateTime.now());
		int ivSize = 16;
        byte[] iv = new byte[ivSize];
        SecureRandom random2 = new SecureRandom();
        random2.nextBytes(iv);
		
		final int CERTAINTY = 256;
        final SecureRandom random = new SecureRandom();

        final BigInteger secret = new BigInteger(iv);
		System.out.println("secret created: " + LocalDateTime.now());
		System.out.println(secret);
        
        
        // prime number must be longer then secret number
        final BigInteger prime = new BigInteger(secret.bitLength() + 1, CERTAINTY, random);
		System.out.println("prime created: " + LocalDateTime.now());
		System.out.println(prime);

		
        // 2 - at least 2 secret parts are needed to view secret
        // 5 - there are 5 persons that get secret parts
        final SecretShare[] shares = Shamir.split(secret, 2, 5, prime, random);


        // we can use any combination of 2 or more parts of secret
        SecretShare[] sharesToViewSecret = new SecretShare[] {shares[0],shares[1]}; // 0 & 1
        BigInteger result = Shamir.combine(sharesToViewSecret, prime);

        sharesToViewSecret = new SecretShare[] {shares[1],shares[4]}; // 1 & 4
        result = Shamir.combine(sharesToViewSecret, prime);

        sharesToViewSecret = new SecretShare[] {shares[0],shares[1],shares[3]}; // 0 & 1 & 3
        result = Shamir.combine(sharesToViewSecret, prime);
        System.out.println(LocalDateTime.now());
        Base64.Encoder encoder = Base64.getEncoder();
        
        System.out.println(encoder.encodeToString(shares[0].getShare().toByteArray()));
        System.out.println(shares[0].getShare().toString(16));
	}
	
}
