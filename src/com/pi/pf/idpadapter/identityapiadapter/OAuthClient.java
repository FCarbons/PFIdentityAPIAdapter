package com.pi.pf.idpadapter.identityapiadapter;

public class OAuthClient {
	
	String oAuthServerUrl;
	String clientId;
	String clientSecret;
	
	public OAuthClient(String oAuthServerUrl, String clientId, String clientSecret) {
		super();
		this.oAuthServerUrl = oAuthServerUrl;
		this.clientId = clientId;
		this.clientSecret = clientSecret;
	}
	
	
	
	public String getoAuthServerUrl() {
		return oAuthServerUrl;
	}
	public void setoAuthServerUrl(String oAuthServerUrl) {
		this.oAuthServerUrl = oAuthServerUrl;
	}
	public String getClientId() {
		return clientId;
	}
	public void setClientId(String clientId) {
		this.clientId = clientId;
	}
	public String getClientSecret() {
		return clientSecret;
	}
	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}
	
	
}
