package com.icicibank.apimngmnt.HybridEncDec;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
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
import java.util.Map;
import java.util.Random;

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

public class Encryption implements Execution{

	private Map<String, String> properties; // read-only

	public Encryption(Map<String, String> properties) {
		this.properties = properties;
	}

	// static Logger logger = Logger.getLogger(IviewController.class);
//	static final String PUBLIC_CERTIFICATE = "D:\\Jagdeep\\ARFIN\\ICICIUATpubliccert\\ICICIUATpubliccert.cer";
	//static final String PUBLIC_CERTIFICATE = "C:\\Users\\jitendra_rawat\\Downloads\\privatePublic\\privatePublic\\RSA-PublicCert.cer";

	public static void main(String[] args) {

		Encryption obj = new Encryption();

		System.out.println(obj.encryptData("{\r\n" + "    \"data\":\"value\"\r\n" + "}","-----BEGIN CERTIFICATE-----\r\n" + 
				"MIIE7jCCAtagAwIBAgIIWmFBujLqylAwDQYJKoZIhvcNAQEMBQAwFTETMBEGA1UEAwwKcnNhX2Fw\r\n" + 
				"aWtleTAeFw0xODEwMzAwNDQ3MThaFw0yMzEwMjkwNDQ3MThaMBUxEzARBgNVBAMMCnJzYV9hcGlr\r\n" + 
				"ZXkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCwjBVK1CLppIwsFm7e+Fp85Hk1Mw2n\r\n" + 
				"5Nc/DKT/pWhpJB8OdlpJA9iF23hrxfbXkrBfCkgvV4Ek4fY1byOnkA7hZq4dYTASCAm89oLwWDNm\r\n" + 
				"0OGNh7E6T7/JoNtjtT0Gh8lJTvpUgHFGg3tiYCScAqul+fS6Rc8+5THk3L9zLzme6eqjkzwBx/ZV\r\n" + 
				"XBIZlAwFkVKbfLFg51LiVoOUz6zXD7nAsMyNhKAgybvqulV07eGzafZ1IBgzpcw5qo0PAd1mTqfy\r\n" + 
				"U+CK9hVeNPPspT16qQWd5xa+fa6BEjuGCumVnFLTbSTRAF5h3QAfvMlkpLdejlXJwvTVQ79Zg5C8\r\n" + 
				"Hu/yWB7tOJBncIKue7KSpwn+vkMws79wpAB5mL4tD3kVCDf2Og7wbtt87v5rcazxF7eZFbsADzHV\r\n" + 
				"oSftdkw5S7iXgh82/CHbRXhzPfG8Zd2v1ksW+Bfnn3czEIMGOSJrKfMbyCYtVMihoi0/L6SHA7++\r\n" + 
				"N9aRrQvfK9PeXnlHgf8pErGUdpjnwdV0tu5atSgf/iBuRgVgUL6t6MFbnBsTQUmZYiQRcsqxOVdy\r\n" + 
				"yfp4DOLgFHGJ1D/isgR/ypalIXMmhuK8GdZ7hukEDX2Dc3js8OkPnFLq6Ps4NIGESfbZSeyINoZX\r\n" + 
				"5GGxdgD/GpokKMHr5bsI3TQujCvzuxShPhUArzCs6TgPmwIDAQABo0IwQDAdBgNVHQ4EFgQUyNoW\r\n" + 
				"eeLVSzVybz7gcZnZlj01cv4wHwYDVR0jBBgwFoAUyNoWeeLVSzVybz7gcZnZlj01cv4wDQYJKoZI\r\n" + 
				"hvcNAQEMBQADggIBADuwEh31OI66oSMB6a79Pd6WSqiyD2NBskdRF7st7CRP5vqeH4P/4srNFAqC\r\n" + 
				"9CjsOmXmSpZFckYQ4zgtqnVQBY7jQlCuSHmg8/Lr1qIzRsMvQmhvp6DJ+bEfQgqcJ+a6tR9cH6hD\r\n" + 
				"VahoMZDEpt3J0fIp30z+O7wJ03K6q5Di/rNey6Ac3GoZwlCi8OFCTmwihcn56I+ssxAqzlq53hzO\r\n" + 
				"iBLLmcMTrWSJWePPkYEhrbBxywg1qJRRGWwkfr1dbRZ22umLHU0R/QdK+jQtqyzghqJpd3T/lHzK\r\n" + 
				"uzAsa0s1R+qMqurKu6mulcLp/XmZpY+Fm4T0WRXzcZBf9trkCSO2Z3VvkCTeGu/WAi3UQpx4HfGr\r\n" + 
				"x02m/h8CHCPPO+PKYthpvSR+0jmiVBaaBo029UG0i2oYBTckng2sy0fx0E+rHnR7pk5Worv8BMm5\r\n" + 
				"sewPUkDDJMZhLtm/bd/VxlI/b56vEA7HvupSWzc7xXV8lZOHVEUAotrlXz+Je2MkEEQIDnYUOYhw\r\n" + 
				"78yFMJJddK9tJVRy8tr8I2j6Zi62jQp/Zltq5JOwpOw/9poovd9wgeRBjuFnscoR/YWrNdPjsjpJ\r\n" + 
				"g/CCb6mthz4R2Mu4enD1YghW7w5darrlUHaYAk+SnwWhMwDwZWWfrVNeEaNq/t/gRm/Ljy+Of3lA\r\n" + 
				"nztA1PrT4bk1KvZX\r\n" + 
				"-----END CERTIFICATE-----\r\n" + 
				""));
	}
	
	@Override
	public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
		try {
			String strOne = resolveVariable(this.properties.get("encData"), messageContext);
			String strTwo = resolveVariable(this.properties.get("publicKey"), messageContext);
			//String strTwo = resolveVariable(this.properties.get("Trandata"), messageContext);
			messageContext.setVariable("encData", strOne);
			messageContext.setVariable("publicKey", strTwo);
			//messageContext.setVariable("Trandata", strTwo);
			String result = encryptData(strOne,strTwo);
			
			messageContext.setVariable("encryptedData", result);
			//messageContext.setVariable("stage", stage);
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


	public String encryptData(String incomingData,String publicKey) {

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
			data = getiViewResponse(sb,publicKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return data;
	}

	public String getiViewResponse(StringBuilder XMLRequest,String publicKey) throws Exception {
		String randomNumber = generateRandom(16);
		String randomNumberiv = generateRandom(16);
		String Encryptedkey = getRequestkey(randomNumber,publicKey);
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
			// Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7PADDING");

			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
			strToEncrypt = ivKey + strToEncrypt;
			byte[] encrypted = cipher.doFinal(strToEncrypt.getBytes());
			return Base64.getEncoder().encodeToString((encrypted));
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	private String getRequestkey(String randomNUmber,String publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
		Cipher ci = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		// X509Certificate cert = getCertificate(PUBLIC_CERTIFICATE);

		X509Certificate cert = getCertificate(publicKey);
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

	private X509Certificate getCertificate(String publicKey) {

		X509Certificate cert = null;
		try {
			//InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream("RSA-PublicCert.cer");
			
			 StringBuilder certLines = new StringBuilder();
		        BufferedReader rdr = new BufferedReader(new StringReader(publicKey));
		        String line;
		        while ((line = rdr.readLine()) != null) {
		        	certLines.append(line);
		        }

		        // Remove the "BEGIN" and "END" lines, as well as any whitespace

		        String certPem = certLines.toString();
		        certPem = certPem.replace("-----BEGIN CERTIFICATE-----", "");
		        certPem = certPem.replace("-----END CERTIFICATE-----", "");
		        certPem = certPem.replaceAll("\\s+","");
			byte [] keybytes=Base64.getDecoder().decode(certPem);
			CertificateFactory f = CertificateFactory.getInstance("X.509");
			cert = (X509Certificate) f.generateCertificate(new ByteArrayInputStream(keybytes));
			//inputStream.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return cert;
	}



	
	public Encryption() {
		super();
		// TODO Auto-generated constructor stub
	}

	
}
