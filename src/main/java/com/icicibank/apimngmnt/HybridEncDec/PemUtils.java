package com.icicibank.apimngmnt.HybridEncDec;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;




public class PemUtils {

	//public static Logger logger=LoggerFactory.getLogger(PemUtils.class);
	
	public static void main(String[] args) {
		
		//logger.info(" "+getPublicKey(Base64.getDecoder().decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnxFW94IEYunr/Y1wpMXBCGbMfNgUQnac1PTNosS/jOVVrj1zntyfYGDhMAImXI3V7LtnV8fg9G1895Yo2ujyBl7E47eYyevITDnPxb5ii2MTLaOllI5foT4pmaxkNA9qiAzYULfNRjss4Nb7Mw8rdpgaCHGfucCqWJO5mjwRdYL7SmOaqWmTQmrPbSeTkdp1j4wZhhtyShTDXV4rn6bqIGyndSHJ94YifK9mfAynoHyguWjzoLQ06BXpWZoWUYnDQA69raC5oaIGCx91Lc8Sfgyh8nsuXaPD7lVyLQNvkdQ9MFyPoiTUQ1+w41yQJyPFM5M6bgUpkoGCkQI+0kII1QIDAQAB"), "RSA"));
		
		/*
		 * try { System.out.println(" "+readPrivateKeyFromFile(
		 * "C:\\Users\\jitendra_rawat\\Desktop\\Trulioo\\icici_privateKey.txt", "RSA"));
		 * } catch (IOException e) { // TODO Auto-generated catch block
		 * e.printStackTrace(); }
		 */
	}
	/*
	 * private static byte[] parsePEMFile(File pemFile) throws IOException { if
	 * (!pemFile.isFile() || !pemFile.exists()) { throw new
	 * FileNotFoundException(String.format("The file '%s' doesn't exist.",
	 * pemFile.getAbsolutePath())); } PemReader reader = new PemReader(new
	 * FileReader(pemFile)); PemObject pemObject = reader.readPemObject(); byte[]
	 * content = pemObject.getContent(); reader.close(); return content; }
	 */

    public static PublicKey getPublicKey(byte[] keyBytes, String algorithm) {
        PublicKey publicKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            publicKey = kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
        	System.out.println("Could not reconstruct the public key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
           System.out.println("Could not reconstruct the public key");
        }

        return publicKey;
    }

	/*
	 * public static RSAPrivateKey readPrivateKeySecondApproach(File file) throws
	 * IOException { try (FileReader keyReader = new FileReader(file)) {
	 * 
	 * PEMParser pemParser = new PEMParser(keyReader); JcaPEMKeyConverter converter
	 * = new JcaPEMKeyConverter(); PrivateKeyInfo privateKeyInfo =
	 * PrivateKeyInfo.getInstance(pemParser.readObject());
	 * 
	 * pemParser.close(); return (RSAPrivateKey)
	 * converter.getPrivateKey(privateKeyInfo);
	 * 
	 * } }
	 */
    private static PrivateKey getPrivateKey(byte[] keyBytes, String algorithm) {
        PrivateKey privateKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            privateKey = kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
        	System.out.println("Could not reconstruct the private key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
        	System.out.println("Could not reconstruct the private key");
        }

        return privateKey;
    }

	/*
	 * public static PublicKey readPublicKeyFromFile(String filepath, String
	 * algorithm) throws IOException { byte[] bytes = PemUtils.parsePEMFile(new
	 * File(filepath)); return PemUtils.getPublicKey(bytes, algorithm); }
	 * 
	 * public static PrivateKey readPrivateKeyFromFile(String filepath, String
	 * algorithm) throws IOException { byte[] bytes = PemUtils.parsePEMFile(new
	 * File(filepath)); return PemUtils.getPrivateKey(bytes, algorithm); }
	 * 
	 * public static RSAPrivateKey readPrivateKeyFromFileSecond(String filepath)
	 * throws IOException {
	 * 
	 * return PemUtils.readPrivateKeySecondApproach(new File(filepath)); }
	 */

}
