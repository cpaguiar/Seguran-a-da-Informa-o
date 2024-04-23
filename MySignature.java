import java.security.*;
import java.util.Arrays;

import javax.crypto.*;



public final class MySignature {

    
    private static MySignature instance;
    private static byte[] resumoMensagem;
    private static String patternAssinatura;

    private static PrivateKey chavePrivada;
    private static PublicKey chavePublica;
    private static Cipher cipher;
    private static MessageDigest providerDigest;

    
     private MySignature(String pattern) throws Exception {
         MySignature.patternAssinatura = pattern;
         MySignature.cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); /*"ECIES", "BC"*/
         MySignature.providerDigest = MessageDigest.getInstance(pattern);
    }

    public static MySignature getInstance(String pattern) throws Exception {
        if (instance == null) {
            instance = new MySignature(pattern);
        }
        return instance;
    }


    public void initSign(PrivateKey key) throws Exception {
        MySignature.chavePrivada = key;
        cipher.init(Cipher.ENCRYPT_MODE, MySignature.chavePrivada);
    }

    public void update(byte[] textoPlano) throws Exception {
        MySignature.providerDigest.update(textoPlano);
        MySignature.resumoMensagem = MySignature.providerDigest.digest();
    }

    public byte[] sign() throws Exception {
        System.out.println("Digest calculated for message:");
	for(int i = 0; i != MySignature.resumoMensagem.length; i++)
		System.out.print(String.format("%02X", MySignature.resumoMensagem[i]));

        return MySignature.cipher.doFinal(MySignature.resumoMensagem);
    }

    public void initVerify(PublicKey key) throws Exception{
        MySignature.chavePublica = key;

        cipher.init(Cipher.DECRYPT_MODE, MySignature.chavePublica);
    }

    public boolean verify(byte[] assinatura) throws Exception {
        byte[] DigestAssinatura = MySignature.cipher.doFinal(assinatura);
        System.out.println("Digest obtained from decrypting digital signature:");
		for(int i = 0; i != DigestAssinatura.length; i++)
			System.out.print(String.format("%02X", DigestAssinatura[i]));
    
        return Arrays.equals(MySignature.resumoMensagem, DigestAssinatura);
    }

}
