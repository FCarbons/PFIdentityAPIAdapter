package com.pi.pf.idpadapter.identityapiadapter.handlers;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.websso.servlet.adapter.Handler;

import com.pi.pf.idpadapter.identityapiadapter.Const;
import com.pi.pf.idpadapter.identityapiadapter.ErrorMessage;
import com.pi.pf.idpadapter.identityapiadapter.IdentityAPIException;
import com.pi.pf.idpadapter.identityapiadapter.OAuthClient;
import com.pingidentity.sdk.oauth20.AccessTokenIssuer;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.SearchResultEntry;

public class LinkIdentityServlet extends AbstractIdentityAPIServlet implements Handler {
	private String[] mandatoryFields = { Const.MOBILE_NUMBER };
	
	private static final long serialVersionUID = 1L;
	final Log log = LogFactory.getLog(this.getClass());

	protected Map<String, OAuthClient> servers = new HashMap<String, OAuthClient>();

	public LinkIdentityServlet(Configuration configuration) {
		super(configuration);
		log.debug("Creating LinkIdentityServlet " + configuration);
		servers.put("it", new OAuthClient("https://veon-it-opco.ping-eng.com:9031/as/token.oauth2", "VeonGlobal", "Password01"));
		servers.put("ru", new OAuthClient("https://veon-ru-opco.ping-eng.com:9031/as/token.oauth2", "VeonGlobal", "Password01"));
	}

	@Override
	public void handle(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.debug("*** Starting handle");
		
		// get the headers from PA
		String emailFromHeader = req.getHeader(Const.EMAIL_ATTRIBUTE_NAME);
		String globalUIDFromHeader = req.getHeader(Const.GLOBAL_UID);

		if (StringUtils.isEmpty(emailFromHeader) || StringUtils.isEmpty(globalUIDFromHeader)) {
			log.error ("Email or globalUID header empty, returning error");
			sendResponse(resp, new ErrorMessage(ErrorMessage.IDENTITY_NOT_FOUND));
			return;
		}

		try {
			
			JSONObject request = getRequestJSONObject(req);
			String countryCode  = getCountryCodeFromNumber (request);
			
			request.put(Const.COUNTRY, countryCode);
			request.put(Const.EMAIL_ATTRIBUTE_NAME, emailFromHeader);
			request.put(Const.GLOBAL_UID, globalUIDFromHeader);
			
			mandadoryFieldsExist(request, mandatoryFields);
			
			log.debug("Request after headers injection: " + request.toString());
			if (userExistsByEmail(request)) {
				request.put(Const.TOKEN, getAccessToken(servers.get(countryCode), getAttribute (request,Const.MOBILE_NUMBER), generateTokenRequest(Const.MOBILE_NUMBER)));
				linkIdentity(request);
				sendResponse(resp, getSuccessResponseJSON(),HttpServletResponse.SC_OK);
			} else {
				sendResponse(resp, new ErrorMessage(ErrorMessage.IDENTITY_NOT_FOUND));
			}

		} catch (IdentityAPIException e) {
			sendResponse(resp, e.getError());
			log.error(e);
		} catch (JSONException e) {
			log.error (e);
		}
		log.debug("*** Exiting handle");
	}

	private String getCountryCodeFromNumber(JSONObject request) throws IdentityAPIException {
		String number = getAttribute(request, Const.MOBILE_NUMBER);
		if (number.startsWith("39") || number.startsWith("+39") || number.startsWith("0039")) {
			log.debug("Derived country it");
			return "it";
		}
		
		if (number.startsWith("7") || number.startsWith("+7") || number.startsWith("007")) {
			log.debug("Derived country ru");
			return "ru";
		}
		
		log.debug("No match found, default to it");
		return "it";
		
	}

	private void linkIdentity(JSONObject request) throws IdentityAPIException {
		log.debug("Starting linkIdentity");
		LDAPConnection connection = getLDAPConnection();
		Collection<Attribute> set = getLDAPAttributeSet(request);
		try {
			SearchResultEntry linkedID = connection.getEntry(getLinkedIDDn(request));
			if (linkedID != null) {
				log.debug("Identity already linked, updating token");
				connection.modify(getLinkedIDDn(request), new Modification(ModificationType.REPLACE, Const.TOKEN, getAttribute(request, Const.TOKEN)));
			} else {
				log.debug("Identity not linked, creating the new link");
				connection.add(getLinkedIDDn(request), set);
			}
		} catch (LDAPException e) {
			log.error(e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.GENERIC_LDAP_ERROR));
		} 
	}

	private Collection<Attribute> getLDAPAttributeSet(JSONObject requestData) throws IdentityAPIException {
		Collection<Attribute> set = new HashSet<Attribute>();
		set.add(new Attribute("objectClass", "top"));
		set.add(new Attribute("objectClass", Const.LINKED_ID_OBJECTCLASS));
		set.add(new Attribute(Const.GLOBAL_UID, getAttribute(requestData, Const.GLOBAL_UID)));
		set.add(new Attribute(Const.LINKED_UID, getAttribute(requestData, Const.MOBILE_NUMBER)));
		set.add(new Attribute(Const.TOKEN, getAttribute(requestData, Const.TOKEN)));
		return set;
	}

	public String getAccessToken(OAuthClient client, String userName, String userCredential) throws IdentityAPIException {
		try {
			log.debug("Starting getAccessToken");
			X509TrustManager tm = null;
			HostnameVerifier hv = null;
			SSLSocketFactory socketFactory = null;

			URL u = new URL(client.getoAuthServerUrl());
			log.debug("Getting token from server: " + u.toString () + " with client: " + client.getClientId());
			HttpsURLConnection con = null;

			tm = new X509TrustManager() {
				public void checkClientTrusted(X509Certificate[] x509Certs, String s) throws CertificateException {
				}

				public void checkServerTrusted(X509Certificate[] x509Certs, String s) throws CertificateException {
				}

				public X509Certificate[] getAcceptedIssuers() {
					return new X509Certificate[0];
				}
			};
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(null, new TrustManager[] { tm }, null);
			socketFactory = sslContext.getSocketFactory();
			con = (HttpsURLConnection) u.openConnection();
			con.setSSLSocketFactory(socketFactory);

			hv = new HostnameVerifier() {
				public boolean verify(String urlHostName, SSLSession session) {
					return true;
				}

			};

			con.setHostnameVerifier(hv);
			con.setRequestMethod("POST");
			String authString = client.getClientId() + ":" + client.getClientSecret();
			con.setRequestProperty("Authorization", "Basic " + Base64.getEncoder().encodeToString(authString.getBytes("utf-8")));
			String postParameters = String.format("client_id=%s&grant_type=password&username=%s&password=%s", client.getClientId(), userName, userCredential);
			log.debug("Post parameter: " + postParameters);
			con.setDoOutput(true);
			DataOutputStream wr = new DataOutputStream(con.getOutputStream());
			wr.writeBytes(postParameters);
			wr.flush();
			wr.close();

			int statusCode = con.getResponseCode();
			log.debug("Response code " + statusCode);

			InputStream is;
			if (statusCode >= 200 && statusCode < 400) {
				// Create an InputStream in order to extract the response object
				is = con.getInputStream();
			} else {
				is = con.getErrorStream();
			}

			BufferedReader in = new BufferedReader(new InputStreamReader(is));
			String inputLine;
			StringBuffer response = new StringBuffer();

			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}
			in.close();
			log.debug("Call completed " + response.toString());
			return response.toString();
		} catch (KeyManagementException | NoSuchAlgorithmException | IOException e) {
			log.error (e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.TOKEN_EXCHANGE_ERROR));
		}
	}

	protected String generateTokenRequest(String linkedID) {
		Map<String, Object> requestAttributes = new HashMap<String, Object>();
		requestAttributes.put("sub", linkedID);
		String token = AccessTokenIssuer.issueToken(requestAttributes, "", "VeonGlobal", "JWT");
		log.debug("Generated token " + token);
		return token;
	}

	public static void main(String[] args) {

	}

}
