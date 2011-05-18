import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Encrypt {

	public static Scanner in;

	public static void main(String[] args) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		Misc func = new Misc();

		//read in the message to be encrypted
		System.out.println("Reading in from " + args[0]);
		File newFile = new File(args[0]);
		in = new Scanner(newFile);
		in.useDelimiter(System.getProperty("line.separator"));
		String message = "";
		while (in.hasNext()) {
			message += in.next();
		}
		System.out.println("Plaintext: " + message);
		System.out.println();
		in.close();

		//read in the public key of Bob for message encryption
		File newFileTwo = new File("bob-pkepk.txt");
		in = new Scanner(newFileTwo);
		String pkepk = in.next();
		byte[] bobPubKey = func.hexToByte(pkepk);
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(bobPubKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
		in.close();

		//read in the private key Alice generated to sign the message
		File newFileThree = new File("alice-dspvk.txt");
		in = new Scanner(newFileThree);
		String dspvk = in.next();
		byte[] aliceSigPrivKey = func.hexToByte(dspvk);
		PKCS8EncodedKeySpec sigPrivKeySpec = new PKCS8EncodedKeySpec(aliceSigPrivKey);
		KeyFactory keyFactoryTwo = KeyFactory.getInstance("RSA");
		PrivateKey sigPrivKey = keyFactoryTwo.generatePrivate(sigPrivKeySpec);
		in.close();

		//generate symmetric secret key
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		keygen.init(128); //AES default length
		SecretKey sKey = keygen.generateKey();
		byte[] rawSecretKey = sKey.getEncoded();
		SecretKeySpec sKeySpec = new SecretKeySpec(rawSecretKey, "AES");
		byte[] symmetricSK = sKeySpec.getEncoded();
		System.out.println("Symmetric Secret Key: " + func.byteToHex(sKeySpec.getEncoded()));
		System.out.println();

		//encrypt the symmetric secret key
		SecureRandom random = new SecureRandom();
		byte[] input = symmetricSK;
		Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
		byte[] encodedSSK = cipher.doFinal(input);
		System.out.println("Encrypted SSK: " + func.byteToHex(encodedSSK));

		//generate random seed for IV (for CBC)
		SecureRandom randomTwo = new SecureRandom();
		byte[] ivInit = randomTwo.generateSeed(16);
		IvParameterSpec iv = new IvParameterSpec(ivInit);
		System.out.println("IV for AES/CBC: " + func.byteToHex(iv.getIV()));

		//initialize AES/CBC
		Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipherAES.init(Cipher.ENCRYPT_MODE, sKeySpec, iv);

		//encrypt plain-text
		byte[] encodedMessage = cipherAES.doFinal(message.getBytes());
		System.out.println("Encrypted message: " + func.byteToHex(encodedMessage));

		//generate digital signature based on current message
		String output = func.byteToHex(encodedSSK) + " " + func.byteToHex(encodedMessage)
				+ " " + func.byteToHex(iv.getIV());
		byte[] data = output.getBytes();/*this is not the original ssk/message/iv, but instead the
		ASCII bit representation of its value in hex.  This is done to simplify verification */
		Signature sig = Signature.getInstance("MD5WithRSA");
		sig.initSign(sigPrivKey);
		sig.update(data);
		byte[] signatureBytes = sig.sign();
		output += " " + func.byteToHex(signatureBytes);
		System.out.println("Digital Signature: " + func.byteToHex(signatureBytes));
		System.out.println("Ciphertext: " + output);
		System.out.println();

		func.outputText(output, args[1]);

		//clear sensitive data
		func.clear(bobPubKey);
		func.clear(aliceSigPrivKey);
		func.clear(rawSecretKey);
		func.clear(symmetricSK);
		func.clear(input);
		func.clear(encodedSSK);
		func.clear(ivInit);
		func.clear(encodedMessage);
		func.clear(data);
		func.clear(signatureBytes);
	}
}
