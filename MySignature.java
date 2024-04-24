// Bernardo Bulgarelli Teixeira: 2010468
// Camila Perez Aguiar : 1521516

import java.security.*;
import java.util.Arrays;
import javax.crypto.*;

public final class MySignature {

    
    private static MySignature instance;
    private byte[] resumoMensagem;

    private PrivateKey chavePrivada;
    private PublicKey chavePublica;
    private Cipher cipher;
    private MessageDigest providerDigest;

    
     private MySignature(String pattern) throws Exception {
         this.cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); /*"ECIES", "BC"*/
         this.providerDigest = MessageDigest.getInstance(pattern);
    }

    public static MySignature getInstance(String pattern) throws Exception {
        if (instance == null) {
            instance = new MySignature(pattern);
        }
        return instance;
    }

    public void initSign(PrivateKey key) throws Exception {
        this.chavePrivada = key;
        cipher.init(Cipher.ENCRYPT_MODE, this.chavePrivada);
    }

    public void update(byte[] textoPlano) throws Exception {
        this.providerDigest.update(textoPlano);
        this.resumoMensagem = this.providerDigest.digest();
    }

    public byte[] sign() throws Exception {
        System.out.println("Digest calculated for message:");
	for(int i = 0; i != this.resumoMensagem.length; i++)
		System.out.print(String.format("%02X", this.resumoMensagem[i]));

        return this.cipher.doFinal(this.resumoMensagem);
    }

    public void initVerify(PublicKey key) throws Exception{
        this.chavePublica = key;

        cipher.init(Cipher.DECRYPT_MODE, this.chavePublica);
    }

    public boolean verify(byte[] assinatura) throws Exception {
        byte[] DigestAssinatura = this.cipher.doFinal(assinatura);
        System.out.println("Digest obtained from decrypting digital signature:");
		for(int i = 0; i != DigestAssinatura.length; i++)
			System.out.print(String.format("%02X", DigestAssinatura[i]));
    
        return Arrays.equals(this.resumoMensagem, DigestAssinatura);
    }

}
