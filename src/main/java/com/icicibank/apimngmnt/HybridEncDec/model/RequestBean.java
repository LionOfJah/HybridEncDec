package com.icicibank.apimngmnt.HybridEncDec.model;

public class RequestBean {
	private String encryptedData;
	private String encryptedKey;
	public String getEncryptedData() {
		return encryptedData;
	}
	public void setEncryptedData(String encryptedData) {
		this.encryptedData = encryptedData;
	}
	public String getEncryptedKey() {
		return encryptedKey;
	}
	public void setEncryptedKey(String encryptedKey) {
		this.encryptedKey = encryptedKey;
	}
	
	
}
