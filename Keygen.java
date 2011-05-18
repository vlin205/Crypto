import java.security.*;

public class Keygen {
	/*
	 * Ordinarily Key Generation would be done with 2 different programs, one for Alice and
	 * one run by Bob, but for the purposes of this project they are done in the same file.
	 */

	public static void main(String[] args) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		Misc func = new Misc();

		//initialize the key generator (KG) and generate the public/private key pair
		SecureRandom random = new SecureRandom();
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
		generator.initialize(1024, random);
		KeyPair pair = generator.generateKeyPair();

		/* initialize KG for digital signature and generate public/private keys for digital signatures
		   It is generally not recommended to use the same public/private key pair for both encryption
		   and digital signatures */
		KeyPairGenerator generatorTwo = KeyPairGenerator.getInstance("RSA");
		generatorTwo.initialize(1024);
		KeyPair sigKeyPair = generatorTwo.generateKeyPair();

		byte[] sigPubKey = sigKeyPair.getPublic().getEncoded();
		byte[] sigPrivKey = sigKeyPair.getPrivate().getEncoded();
		byte[] pubKey = pair.getPublic().getEncoded();
		byte[] privKey = pair.getPrivate().getEncoded();

		//output the generated keys
        func.outputText(func.byteToHex(sigPubKey), "alice-dspk.txt");
        func.outputText(func.byteToHex(sigPrivKey), "alice-dspvk.txt");
        func.outputText(func.byteToHex(pubKey), "bob-pkepk.txt");
        func.outputText(func.byteToHex(privKey), "bob-pkepvk.txt");

        //clear sensitive data
		func.clear(sigPubKey);
		func.clear(sigPrivKey);
		func.clear(pubKey);
		func.clear(privKey);
	}
}
