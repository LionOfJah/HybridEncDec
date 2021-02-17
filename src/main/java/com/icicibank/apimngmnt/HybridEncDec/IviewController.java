package com.icicibank.apimngmnt.HybridEncDec;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import com.icicibank.apimngmnt.HybridEncDec.model.RequestBean;



public class IviewController {

	//static Logger logger = Logger.getLogger(IviewController.class);
//	static final String PUBLIC_CERTIFICATE = "D:\\Jagdeep\\ARFIN\\ICICIUATpubliccert\\ICICIUATpubliccert.cer";
	static final String PUBLIC_CERTIFICATE = "C:\\Users\\jitendra_rawat\\Downloads\\privatePublic\\privatePublic\\RSA-PublicCert.cer";
	
	public static void main(String[] args) {
		
		IviewController obj = new IviewController();
		
		System.out.println(obj.encryptData("{\r\n" + 
				"    \"data\":\"lauda mera\"\r\n" + 
				"}"));
	}
	public String encryptData(String incomingData) {
		
		StringBuilder sb = new StringBuilder();
		try {
			BufferedReader br = new BufferedReader(new StringReader(incomingData));
			String line = null;
			while ((line = br.readLine()) != null) {
				sb.append(line.trim());
			}
		} catch (Exception e) {
			e.printStackTrace();
			
		}
		
		String data = null;
		try {
			data = getiViewResponse(sb);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return data;
	}

	public String getiViewResponse(StringBuilder XMLRequest) throws Exception {
		String randomNumber = generateRandom(16);
		String randomNumberiv = generateRandom(16);
		String Encryptedkey = getRequestkey(randomNumber);
		String EncryptedData = getRequestData(randomNumber, randomNumberiv, XMLRequest.toString());
		String responseData = "{\r\n" + "    \"requestId\": \"\",\r\n" + "    \"service\": \"\",\r\n"
				+ "    \"encryptedKey\": \"" + Encryptedkey + "\",\r\n" + "    \"oaepHashingAlgorithm\": \"NONE\",\r\n"
				+ "    \"iv\": \"\",\r\n" + "    \"encryptedData\": \"" + EncryptedData + "\",\r\n"
				+ "    \"clientInfo\": \"\",\r\n" + "    \"optionalParam\": \"\"\r\n" + "}";
		return responseData;
	}

	public String generateRandom(int prefix) {
		Random rand = new Random();

		long x = (long) (rand.nextDouble() * 100000000000000L);

		String s = String.valueOf(prefix) + String.format("%014d", x);
		return s;
	}

	private String getRequestData(String secretKey, String ivKey, String strToEncrypt)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {

		try {
			IvParameterSpec iv = new IvParameterSpec(ivKey.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(secretKey.getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			//Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7PADDING");
			
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
			strToEncrypt = ivKey + strToEncrypt;
			byte[] encrypted = cipher.doFinal(strToEncrypt.getBytes());
			return Base64.getEncoder().encodeToString((encrypted));
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	private String getRequestkey(String randomNUmber) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
		Cipher ci = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		//X509Certificate cert = getCertificate(PUBLIC_CERTIFICATE);
		
		X509Certificate cert = getCertificate();
		ci.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());

		byte[] input = randomNUmber.getBytes("UTF-8");
		String key = Base64.getEncoder().encodeToString(ci.doFinal(input));

		return key;
	}

	/*
	 * private X509Certificate getCertificate(String path) { logger.info("file is :"
	 * + path); X509Certificate cert = null; try { FileInputStream inputStream = new
	 * FileInputStream(path); CertificateFactory f =
	 * CertificateFactory.getInstance("X.509"); cert = (X509Certificate)
	 * f.generateCertificate(inputStream); inputStream.close();
	 * logger.info("Certificate Public Key is :" + cert.getPublicKey()); } catch
	 * (FileNotFoundException e) { e.printStackTrace(); } catch (Exception e) {
	 * e.printStackTrace(); }
	 * 
	 * return cert; }
	 */
	
	private X509Certificate getCertificate() {
		
		X509Certificate cert = null;
		try {
			InputStream inputStream =  this.getClass().getClassLoader().getResourceAsStream("RSA-PublicCert.cer");
			CertificateFactory f = CertificateFactory.getInstance("X.509");
			cert = (X509Certificate) f.generateCertificate(inputStream);
			inputStream.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return cert;
	}

	/**************************
	 * Decryption
	 * 
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws UnrecoverableKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 ***************************/

	static final String KEYSTORE_FILE = "C:\\Users\\jitendra_rawat\\Downloads\\privatePublic\\privatePublic\\privateKey.p12";
	static final String KEYSTORE_PWD = "123";
	static final String KEYSTORE_ALIAS = "rsa_apikey";
	static final String KEYSTORE_INSTANCE = "PKCS12";
	static final String ASYMM_CIPHER = "RSA/ECB/PKCS1Padding";
	
	
	public String DecryptData(InputStream incomingData) throws UnrecoverableKeyException, CertificateException,
			KeyStoreException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		StringBuilder sb = new StringBuilder();
		try {
			BufferedReader br = new BufferedReader(new InputStreamReader(incomingData));
			String line = null;
			while ((line = br.readLine()) != null) {
				sb.append(line.trim());
			}
		} catch (Exception e) {
			e.printStackTrace();
			
		}
		
		RequestBean reqData = null;

		reqData = new Gson().fromJson(sb.toString(), RequestBean.class);
		String secretKey = null;
		try {

			secretKey = decryptKey(reqData.getEncryptedKey(), KEYSTORE_FILE);
			
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | UnsupportedEncodingException
				| IllegalBlockSizeException | BadPaddingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		byte[] ivrec = getIVSpec(reqData.getEncryptedData());
		String decryptResponse = getDecryptdata(reqData.getEncryptedData(), secretKey, ivrec);
		
		decryptResponse = decryptResponse.substring(decryptResponse.indexOf("{"), decryptResponse.length());
		return decryptResponse;
	}

	public  String decryptKey(String b64EncryptedMsg, String filePath)
			throws NoSuchAlgorithmException, NoSuchPaddingException, CertificateException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, IOException {
		Cipher cipher = Cipher.getInstance(ASYMM_CIPHER);
		Key key = loadPrivateKeyFromFile(filePath);
		byte[] encryptedMsg = Base64.getDecoder().decode(b64EncryptedMsg);
		
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedMsg = cipher.doFinal(encryptedMsg);
		
		return new String(decryptedMsg);
	}

	private  Key loadPrivateKeyFromFile(String privateKeyPath) throws CertificateException, KeyStoreException,
			NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
		Key key = null;
		KeyStore keyStore = KeyStore.getInstance(KEYSTORE_INSTANCE);
		keyStore.load(this.getClass().getClassLoader().getResourceAsStream("privateKey.p12"), KEYSTORE_PWD.toCharArray());
		key = keyStore.getKey(KEYSTORE_ALIAS, KEYSTORE_PWD.toCharArray());
		
		return key;
	}

//	private String getDecryptedData(String secret, String strToDecrypt)
//			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
//			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
//
//		try {
//			SecretKeySpec skeySpec = new SecretKeySpec(secret.getBytes("UTF-8"), "AES");
//
//			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//			cipher.init(Cipher.DECRYPT_MODE, skeySpec);
//			byte[] original = cipher.doFinal(strToDecrypt.getBytes());
//
//			return new String(original, Charset.forName("UTF-8"));
//
//		} catch (Exception ex) {
//			ex.printStackTrace();
//		}
//		return null;
//	}

//	private static SecretKeySpec secretKey;
//	private static byte[] key;
//
//	public static void setKey(String myKey) {
//		MessageDigest sha = null;
//		try {
//			key = myKey.getBytes("UTF-8");
//			sha = MessageDigest.getInstance("SHA-1");
//			key = sha.digest(key);
//			key = Arrays.copyOf(key, 16);
//			secretKey = new SecretKeySpec(key, "AES");
//		} catch (NoSuchAlgorithmException e) {
//			e.printStackTrace();
//		} catch (UnsupportedEncodingException e) {
//			e.printStackTrace();
//		}
//	}

	private byte[] getIVSpec(String encryptedData) {

		byte[] IV = Base64.getDecoder().decode(encryptedData.getBytes());
		byte[] resbyte = new byte[16];
		for (int i = 0; i < 16; i++) {
			resbyte[i] = IV[i];
		}
		String result = new String(resbyte);
		
		return resbyte;
	}

	private String removeIV(String encryptedData) {

		byte[] IV = Base64.getDecoder().decode(encryptedData.getBytes());
		byte[] filteredByteArray = Arrays.copyOfRange(IV, 16, IV.length - 16);
		String dataAfterIVRemove = Base64.getEncoder().encodeToString(filteredByteArray);
		return dataAfterIVRemove;
	}

	private String getDecryptdata(String data, String key, byte[] ivrec)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		IvParameterSpec ivspec = new IvParameterSpec(ivrec);
		Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
		byte[] actualkey = key.getBytes();
		SecretKeySpec secretKeySpec = new SecretKeySpec(actualkey, "AES");
		ci.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);
		//ci.init(Cipher.DECRYPT_MODE,secretKeySpec);
		//data=removeIV(data);//remove IV data
		byte[] result = Base64.getDecoder().decode(data.getBytes());
		String decryptedData = new String(ci.doFinal(result));

		return decryptedData;
	}
}
