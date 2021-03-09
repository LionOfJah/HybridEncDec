package com.icicibank.apimngmnt.HybridEncDec;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.apigee.flow.execution.Action;
import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.gson.Gson;
import com.icicibank.apimngmnt.HybridEncDec.model.RequestBean;

public class Decryption implements Execution{
	
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

	//static final String KEYSTORE_FILE = "C:\\Users\\jitendra_rawat\\Downloads\\privatePublic\\privatePublic\\privateKey.p12";
	static final String KEYSTORE_PWD = "123";
	static final String KEYSTORE_ALIAS = "rsa_apikey";
	static final String KEYSTORE_INSTANCE = "PKCS12";
	static final String ASYMM_CIPHER = "RSA/ECB/PKCS1Padding";
	
	private Map<String, String> properties; // read-only

	public Decryption(Map<String, String> properties) {
		this.properties = properties;
	}

	public static void main(String[] args) {
		Decryption dec= new Decryption();
		try {
			System.out.println(dec.DecryptData("{\r\n" + 
					"    \"requestId\": \"\",\r\n" + 
					"    \"service\": \"\",\r\n" + 
					"    \"encryptedKey\": \"SC2GO1zS7aiYYQ/2Ma6FwE+jIE6w0HzD22Ft0j8ikxw+Rn39IikSVMQTbeg0efD+pn7meIQr5YYdNdM3ptikDnaMIUF+5A36yGYqRrsP6Mpkh4xDmCJkPh4UPc3AGl/z+ff8DUr57ouaZL1O2pL/v/Ud4ltnDF53sAQLcBcYSDyY3Fi4h04IrdP4yQCjq9RvmzTf3xIA55q+hzFmvDUdHiYPqKDFZnUqbu2OR03LqOKOZ1q2GhlfI3A94PbI5tE7LuGRGfxCJNBKIH4CjHRuFxawH9XI276LnOn0dH2pQlwEEoH4Qa+K+i0rMStpMyXiISBZaxnx5rPDQg/yQvCjafwCzgl54306lmF8dWk9CiwpmrIQGfvsuxiptC/A9U18+CenKmstufYoiYEkq3vUVn9NsQ6V44i9gNl+BGZ0lNcw9TY72W1Y325fka3JI8OmtD3hK9ibBoNq5PKBDr565T99qW0YBKMOMr21vmywdZHGsFPJulcfr8AQtAaSVkFqsq+WL+uN6fv2hnRAjO2WNGHmVIiycufxbWBNP0eD7RLOhVEq355ucR89etHIwNo7iFny5GPPiXIK07BcF9ZLR4QK4ZG9LCjgZ/+o7E+ChY2agQ8MHFo1ljmxG/ViOPtiAKox7+7ATAc5Ay2ns1VJBcOC63HXQG5zd8XCmdv6M8U=\",\r\n" + 
					"    \"oaepHashingAlgorithm\": \"NONE\",\r\n" + 
					"    \"iv\": \"\",\r\n" + 
					"    \"encryptedData\": \"pnS3i/VHgbQ9PQ3dNkkqV8EwDtGpQuqt4XTFoLwOgjuiWMAb3aFSL0UmYmjpZrki\",\r\n" + 
					"    \"clientInfo\": \"\",\r\n" + 
					"    \"optionalParam\": \"\"\r\n" + 
					"}\r\n" + 
					"","-----BEGIN PRIVATE KEY-----\r\n" + 
							"MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQCwjBVK1CLppIws\r\n" + 
							"Fm7e+Fp85Hk1Mw2n5Nc/DKT/pWhpJB8OdlpJA9iF23hrxfbXkrBfCkgvV4Ek4fY1\r\n" + 
							"byOnkA7hZq4dYTASCAm89oLwWDNm0OGNh7E6T7/JoNtjtT0Gh8lJTvpUgHFGg3ti\r\n" + 
							"YCScAqul+fS6Rc8+5THk3L9zLzme6eqjkzwBx/ZVXBIZlAwFkVKbfLFg51LiVoOU\r\n" + 
							"z6zXD7nAsMyNhKAgybvqulV07eGzafZ1IBgzpcw5qo0PAd1mTqfyU+CK9hVeNPPs\r\n" + 
							"pT16qQWd5xa+fa6BEjuGCumVnFLTbSTRAF5h3QAfvMlkpLdejlXJwvTVQ79Zg5C8\r\n" + 
							"Hu/yWB7tOJBncIKue7KSpwn+vkMws79wpAB5mL4tD3kVCDf2Og7wbtt87v5rcazx\r\n" + 
							"F7eZFbsADzHVoSftdkw5S7iXgh82/CHbRXhzPfG8Zd2v1ksW+Bfnn3czEIMGOSJr\r\n" + 
							"KfMbyCYtVMihoi0/L6SHA7++N9aRrQvfK9PeXnlHgf8pErGUdpjnwdV0tu5atSgf\r\n" + 
							"/iBuRgVgUL6t6MFbnBsTQUmZYiQRcsqxOVdyyfp4DOLgFHGJ1D/isgR/ypalIXMm\r\n" + 
							"huK8GdZ7hukEDX2Dc3js8OkPnFLq6Ps4NIGESfbZSeyINoZX5GGxdgD/GpokKMHr\r\n" + 
							"5bsI3TQujCvzuxShPhUArzCs6TgPmwIDAQABAoICAQCmXJqD1LrBZ+keclUvjt/V\r\n" + 
							"6IW+98jaeO3L3+JrdDabPQp22lfhjdou6Mzk4brlELlaFZpH4jEzzCnx2DTE5R7g\r\n" + 
							"j51q2fYuR5zFj5V7XeGx9QtWDpOW2ydinE2f+1zyFmo6xk1l61LSm3tdDDPzPyD4\r\n" + 
							"Wj2eecH9BoSpoMpXhBzL/qi4Uzmsg/1AGm6D49ogNPyewDV1lwWnetarF7dLQOpN\r\n" + 
							"BUz73gn2W6LUYZm9gZu5MRSo8gFcSdPUUz5w8dTrXxsrYpao25LvHv7r9BmmyDce\r\n" + 
							"wG/SOSSDQ+cLPKU38gKqcKLMv4gwt8wyG/e6+uxAEegNI8UKYbiiZTOx0YVR3G/m\r\n" + 
							"jpRu0SGzA7BYiJ79FD61pVKHvj4y9l4hCPJArg8IvRTx2TyXHknNIxmZys4FlDYp\r\n" + 
							"umXnUAW8Rst3GDYwJ7SOH2wyK9Xx4EMSM/21aoYKhcowb6FbhL1RU3QLeeRT3Ogp\r\n" + 
							"qw8x53uduIQP1NZ3jihyjaAKIhLTaN2/MKkEhzsvSr8GLqnOYjL7pdizWeFzZcdF\r\n" + 
							"5NEwi+Qu3XXO8QgGjAzjmY99rbcgW8wyljDMXsdGzuBegCR7xqfNZUUwsANuyIWs\r\n" + 
							"DlGZzbFf0+uuYdQGqj1gdC8ohyRTNfCdyF3r+7WnWqUSJOogdO65JaWLitmw1FnF\r\n" + 
							"0wcTtsGzrXyCxdUr0/FoAQKCAQEA7sW9Qx32lsvSbMwChGIrGiABsFz8H18ugC2n\r\n" + 
							"/bXUVTWlc2r4xbihDvbSiGYziNj/T++rMFkPUiXLHItjy9Z+pF06v84vNeBo2JI/\r\n" + 
							"hqlbU2hK44mANtcOZRMll4s0ACYNxUkC9q4XYjs0uIetZlRTiCNNpWMYch+behxz\r\n" + 
							"2L98OmoKBumM2mPWrwd/e9zjOiTCHp1avM5lMmL7KdJl1sNSqQEh3lukMDZioqM3\r\n" + 
							"pTnzeXMTl7bJMacr46jFv4WxlZhpPvb44QpDUdqGd9CvdNYwIQ3E0v734Y4efDG9\r\n" + 
							"sHAGdylXp1i4+7W9xuTXvAHKuEh+/Zn5q00qnLChELNbXZWvAQKCAQEAvUkCVYSr\r\n" + 
							"iQbNQafu6hcaPmhpdcciltToNj0tAKCDtQEosw05tyfdEa7z2DGkSPdvQnwtTR7f\r\n" + 
							"JoW3PkKj5NM3gW1vfafjNCMXZgfDpextgzSJNdPRkR/uAkypFdjqtgayBvJ93F9Q\r\n" + 
							"cVxadve+sC4fWA0hpEyz1ZAKyI925VlA6vU1dIzXHUCnkiwhJzIPomRkPlZ+6Kzl\r\n" + 
							"D+DdtqJ2w9s//y7kWLmnwUKwcOq761jLExbF2SSXfoolAOSaB3/u7OK9HnwzAUrR\r\n" + 
							"nGwqbPKZ5ddirXcbPcYGY0DFC/51UmVuhpZ/I+rs5m+bzlPt3/sns35Blfp2GXCz\r\n" + 
							"EqziAWGSLNEamwKCAQBq7neSJUsXwXQdcUf3TZeL/aWD/ECVNCU5FjlTsCjFeF7+\r\n" + 
							"T3vV4JeQgg1LNKoDsVq1y9nYrynjWjWaNPqegRL6PR5gY9BUyolp5CU7A4F42w4e\r\n" + 
							"1Kds5+b0cRy2v4qsPl6QaeA/5TtnrKgxs+F+IGnAYD8XwEdkZK9WgoOHIEpcRrzy\r\n" + 
							"14lTDL9KZ4s6R3Qjx+5/k2zdfXlolVdyJV2iTpsoQO+QC25+gPyvZXU4M7nMPDMc\r\n" + 
							"EKoN6JYJQL4+xXsASd9oaWaQMe5wK/NomTbalkm7o9TvwWv1wZX5fLU83Q6oMwWk\r\n" + 
							"VmGRqJSzDC1pb0wAN8dXf6uGgeqBfcDEH+7c/HoBAoIBABJL/2TC2U36kVa6Y/bO\r\n" + 
							"2uOTdjZDVI2d8QBlM3dvDKwve36rVZvlx5HRBpMsYUQIXwHfPQXKaSmxHUBwcqVI\r\n" + 
							"4YGqUW+lDepZRga/02KzkvZu2qCQZB6SJpCkVmfdOvrzdLwFLrNhp0X99mSvmAgx\r\n" + 
							"vSfmxQy7uVp4fQJcE9MhqIvNvigRAS47tLcFewLt7OL2r1XzSHs3U0EQrH3eAHr4\r\n" + 
							"M5x4LOyCrbuZtbKEjju2rpKezesqhVZfBiqq7lSxQig11rAes1N5pv9m2UcEwGme\r\n" + 
							"Q1SfQcvb23w2o5WAOFkJowBxhcK0D8hKm5X7OPBAt9q65p4Xwti8syKoAYS+qMGa\r\n" + 
							"SOcCggEBAJ/RUFUI4ukJy7Srn781ABHXwPo3QU0HdWXM5e+s2LDRjOllZGg0R4oh\r\n" + 
							"puyS8EbmeGcfIdFfFLGxYCIFeCG4HLvciKWCSlxtGbAv61LSMtfsY3/rR0MjsMAb\r\n" + 
							"WmLA+iqg33NuPx1QJB9HRHIskbC34zFz1THtlc4e5OeoBDgUWWb8Ev3THB5mRJVg\r\n" + 
							"PBmgpjUM5WCgkLYFV0UO/1rTb/VsPDOEoUeot05lNwyEOBAzObh7gxiXRjA70tUe\r\n" + 
							"VdxWgjov7X+WD6WnubLFOvd1qF3w0AyWdWa1pddz/HTO6e82dqRPEV5JN1+e6zEe\r\n" + 
							"aKdiBykOPfhck/tXqO4R8Ezvk0eUlMU=\r\n" + 
							"-----END PRIVATE KEY-----\r\n" + 
							""));
		} catch (UnrecoverableKeyException | InvalidKeyException | CertificateException | KeyStoreException
				| NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException
				| IllegalBlockSizeException | BadPaddingException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	@Override
	public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
		//ContentLogger contentLogger = new ContentLogger(messageContext, executionContext);
		
		try {
			/*
			 * String decData = resolveVariable("decData", messageContext); String
			 * privateKey = resolveVariable("privateKey", messageContext);
			 * contentLogger.log("decData", decData); contentLogger.log("privateKey",
			 * privateKey);
			 */
			
			  String strOne = resolveVariable(this.properties.get("decData"),
			  messageContext); String strTwo =
			  resolveVariable(this.properties.get("privateKey"), messageContext);
			  messageContext.setVariable("decData", strOne);
			  messageContext.setVariable("privateKey", strTwo);
			  
			  String result = DecryptData(strOne,strTwo); //String mode =
			  resolveVariable("mode", messageContext);
			  messageContext.setVariable("decryptedData", result);
			  //messageContext.setVariable("stage", stage); return ExecutionResult.SUCCESS;
			 
			return ExecutionResult.SUCCESS;
		} catch (Exception ex) {
			ExecutionResult executionResult = new ExecutionResult(false, Action.ABORT);
			executionResult.setErrorResponse(ex.getMessage());
			executionResult.addErrorResponseHeader("ExceptionClass", ex.getClass().getName());
			//messageContext.setVariable("stage", stage);
			messageContext.setVariable("JAVA_ERROR", ex.getMessage());
			messageContext.setVariable("JAVA_STACKTRACE", ex.getClass().getName());
			return ExecutionResult.ABORT;
		}
	}
	
	private String resolveVariable(String variable, MessageContext msgContext) {
	    if (variable.isEmpty())
	      return ""; 
	    if (!variable.startsWith("{") || !variable.endsWith("}"))
	      return variable; 
	    String value = msgContext.getVariable(variable.substring(1, variable.length() - 1)).toString();
	    if (value.isEmpty())
	      return variable; 
	    return value;
	  }
	public String DecryptData(String incomingData,String privateKey) throws UnrecoverableKeyException, CertificateException,
			KeyStoreException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

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

		RequestBean reqData = null;

		reqData = new Gson().fromJson(sb.toString(), RequestBean.class);
		String secretKey = null;
		try {

			secretKey = decryptKey(reqData.getEncryptedKey(), privateKey);

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

	public String decryptKey(String b64EncryptedMsg, String privateKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, CertificateException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, IOException {
		Cipher cipher = Cipher.getInstance(ASYMM_CIPHER);
		Key key = loadPrivateKeyFromFile(privateKey);
		byte[] encryptedMsg = Base64.getDecoder().decode(b64EncryptedMsg);

		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedMsg = cipher.doFinal(encryptedMsg);

		return new String(decryptedMsg);
	}

	private PrivateKey loadPrivateKeyFromFile(String privateKey) throws CertificateException, KeyStoreException,
			NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
		/*
		 * Key key = null; KeyStore keyStore = KeyStore.getInstance(KEYSTORE_INSTANCE);
		 * keyStore.load(this.getClass().getClassLoader().getResourceAsStream(
		 * "privateKey.p12"), KEYSTORE_PWD.toCharArray());
		 */

		 StringBuilder pkcs8Lines = new StringBuilder();
	        BufferedReader rdr = new BufferedReader(new StringReader(privateKey));
	        String line;
	        while ((line = rdr.readLine()) != null) {
	            pkcs8Lines.append(line);
	        }

	        // Remove the "BEGIN" and "END" lines, as well as any whitespace

	        String pkcs8Pem = pkcs8Lines.toString();
	        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
	        pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
	        pkcs8Pem = pkcs8Pem.replaceAll("\\s+","");
	        
	        byte [] pkcs8EncodedBytes = Base64.getDecoder().decode(pkcs8Pem);
	        
	        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
	        KeyFactory kf = KeyFactory.getInstance("RSA");
	        PrivateKey privKey=null;
	        try {
				 privKey = kf.generatePrivate(keySpec);
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		//key = keyStore.getKey(KEYSTORE_ALIAS, KEYSTORE_PWD.toCharArray());

		return privKey;
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
		// ci.init(Cipher.DECRYPT_MODE,secretKeySpec);
		// data=removeIV(data);//remove IV data
		byte[] result = Base64.getDecoder().decode(data.getBytes());
		String decryptedData = new String(ci.doFinal(result));

		return decryptedData;
	}

	public Decryption() {
		super();
		// TODO Auto-generated constructor stub
	}

	



}
