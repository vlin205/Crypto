import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Decrypt {

	public static Scanner in;

	public static void main(String[] args) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		Misc func = new Misc();

		//read in ciphertext
		File newFile = new File(args[0]);
		in = new Scanner(newFile);
		String SSK = in.next();
		String message = in.next();
		String iv = in.next();
		String signature = in.next();
		in.close();

		//read in the public key of Alice for signature verification
		File newFileTwo = new File("alice-dspk.txt");
		in = new Scanner(newFileTwo);
		String dspk = in.next();
		byte[] aliceSigPubKey = func.hexToByte(dspk);
		X509EncodedKeySpec sigPubKeySpec = new X509EncodedKeySpec(aliceSigPubKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey sigPubKey = keyFactory.generatePublic(sigPubKeySpec);
		in.close();

		// read in the private key of Bob
		File newFileThree = new File("bob-pkepvk.txt");
		in = new Scanner(newFileThree);
		String pkepvk = in.next();
		byte[] bobPrivKey = func.hexToByte(pkepvk);
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(bobPrivKey);
		KeyFactory keyFactoryTwo = KeyFactory.getInstance("RSA", "BC");
		PrivateKey privKey = keyFactoryTwo.generatePrivate(privKeySpec);
		in.close();

		//verify the authenticity of the digital signature and output result
		Signature sig = Signature.getInstance("MD5WithRSA");
		sig.initVerify(sigPubKey);
		sig.update((SSK + " " + message + " " + iv).getBytes());
		if(sig.verify(func.hexToByte(signature)) == true)
			System.out.println("The message is authentic.");
		else {
			System.out.println("The message has been tampered with.");
			System.out.println("Ending Program.");
			System.exit(0);
		}

		//decrypt the symmetric secret key
		Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, privKey);
		byte[] decodedSSK = cipher.doFinal(func.hexToByte(SSK));
		System.out.println("Decrypted SSK : " + func.byteToHex(decodedSSK));

		//decrypt the original message
		Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec decKeySpec = new SecretKeySpec(decodedSSK, "AES");
		cipherAES.init(Cipher.DECRYPT_MODE, decKeySpec, new IvParameterSpec(func.hexToByte(iv)));
		byte[] original = cipherAES.doFinal(func.hexToByte(message));
		String originalString = new String(original);
		System.out.println("Decrypted message: " + originalString);
		func.outputText(originalString, args[1]);

		//clear sensitive data
		func.clear(aliceSigPubKey);
		func.clear(bobPrivKey);
		func.clear(decodedSSK);
		func.clear(original);
	}
}
