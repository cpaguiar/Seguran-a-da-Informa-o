// Bernardo Bulgarelli Teixeira: 2010468
// Camila Perez Aguiar : 1521516

import java.security.*;
import javax.crypto.*;
import java.security.spec.*;

public class MySignatureTest {
    public static void main(String[] args) throws Exception{
    
		if (args.length !=2) {
			System.err.println("Erro! A entrada do programa deve ser da seguinte forma: MySignatureTest <Padrao_de_assinatura> <texto_para_ser_assinado>");
				System.exit(1);
		}

		byte[] plainText = args[1].getBytes("UTF8");

		String pattern = null;

		switch(args[0]){
		case "MD5withRSA":
			pattern = "MD5";
			break;
		case "SHA1withRSA":
			pattern = "SHA-1";
			break;
		case "SHA256withRSA":
			pattern = "SHA-256";
			break;
		case "SHA512withRSA":
			pattern = "SHA-512";
			break;
		case "SHA256withECDSA":
			pattern = "SHA-256";
			break;
		default:
			System.out.println("Invalid signature pattern");
			System.exit(1);
		}

		System.out.println( "\nStart generating RSA key" );
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair key = keyGen.generateKeyPair();
		System.out.println( "Finish generating RSA key" );

		System.out.println( "\nStart generating signature" );
		MySignature sig = MySignature.getInstance(pattern);
		sig.initSign(key.getPrivate());

		sig.update(plainText);

		System.out.println( "Generating signature - encrypting digest" );
		byte[] signature = sig.sign();
		System.out.println( "\nFinish generating signature" );

		System.out.println( "\nSignature:" );
		
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < signature.length; i++) {
			String hex = Integer.toHexString(0x0100 + (signature[i] & 0x00FF)).substring(1);
			buf.append((hex.length() < 2 ? "0" : "") + hex);
		}

		System.out.println( buf.toString() );

		System.out.println( "\nStart signature verification" );
		sig.initVerify(key.getPublic());
		sig.update(plainText);
		System.out.println( "Comparing digests to verify signature" );
		try {
			if (sig.verify(signature)) {
				System.out.println( "\nSignature verified" );
			} 
			else System.out.println( "\nSignature failed" );
		} 
		catch (SignatureException se) {
			System.out.println( "\nSingature failed" );
		}
		return;
    }
}
