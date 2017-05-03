package com.pi.pf.idpadapter.identityapiadapter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.domain.datasource.info.LdapInfo;

import com.pingidentity.access.DataSourceAccessor;
import com.pingidentity.adapters.htmlform.pwdreset.common.Constants;
import com.pingidentity.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.pingidentity.adapters.htmlform.pwdreset.model.GeneratedCode;
import com.pingidentity.adapters.htmlform.pwdreset.util.CodeGenerationUtil;
import com.pingidentity.adapters.htmlform.pwdreset.util.TimeUtils;
import com.pingidentity.email.util.EmailHelper;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchResultEntry;

public class AbstractIdentityAPIServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;
	private final Log log = LogFactory.getLog(this.getClass());
	protected Configuration configuration;
	protected LdapInfo ldapInfo;
	private LDAPConnection ldapConnection;

	public AbstractIdentityAPIServlet(Configuration configuration) {
		log.debug("Creating AbstractIdentity: " + configuration);
		this.configuration = configuration;
		String ldapID = configuration.getFieldValue(Const.LDAP_DATASOURCE_NAME);
		log.debug("Ldap ID: " + ldapID);
		ldapInfo = new DataSourceAccessor().getLdapInfo(ldapID);
	}

	protected JSONObject getRequestJSONObject(HttpServletRequest req) throws IOException, JSONException {
		StringBuffer buf = new StringBuffer();
		String line = null;
		BufferedReader reader = req.getReader();
		while ((line = reader.readLine()) != null)
			buf.append(line);

		log.debug("Raw input: " + buf.toString());
		log.debug("Input JSON " + new JSONObject(buf.toString()));
		return new JSONObject(buf.toString());
	}

	protected LDAPConnection getLDAPConnection() throws LDAPException {
		if (ldapConnection == null) {
			log.debug("Creating connection to: " + ldapInfo.getHost());
			ldapConnection = new LDAPConnection(ldapInfo.getHost().split(":")[0], new Integer(ldapInfo.getHost().split(":")[1]).intValue(),
					ldapInfo.getPrincipal(), ldapInfo.getCredentials());
			log.debug("Connection created");
		}
		
		return ldapConnection;
	}

	protected String getGlobalIDDn(JSONObject userData) throws JSONException {
		String baseDN = configuration.getFieldValue(Const.BASE_DN_NAME);
		String mailAddress = userData.getString(Const.EMAIL_ATTRIBUTE_NAME);
		String dn = Const.EMAIL_ATTRIBUTE_NAME + "=" + mailAddress + "," +baseDN.replaceAll("%dir%", "global");
		log.debug("Entry dn " + dn);
		return dn;
	}
	
	protected String getLinkedIDDn(JSONObject userData) throws JSONException {
		String baseDN = configuration.getFieldValue(Const.BASE_DN_NAME);
		String linkedUID = userData.getString(Const.MOBILE_NUMBER);
		String dn = Const.LINKED_UID + "=" + linkedUID + "," + baseDN.replaceAll("%dir%", "it");
		log.debug("Entry dn " + dn);
		return dn;
	}

	protected Collection<Attribute> getAttributeMap(JSONObject userData) throws JSONException {
		Collection<Attribute> set = new HashSet<Attribute>();

		for (String key : JSONObject.getNames(userData)) {
			Attribute attribute = new Attribute(key, userData.get(key).toString());
			set.add(attribute);
		}

		return set;
	}

	protected boolean validateCode(String userInputCode, String generatedHashedCode, String generatedHashedSalt, String issueTimeStamp) {
		byte[] code = DatatypeConverter.parseBase64Binary(generatedHashedCode);
		byte[] salt = DatatypeConverter.parseBase64Binary(generatedHashedSalt);
		if ((userInputCode == null) || (userInputCode.length() == 0)) {
			return false;
		}
		if (CodeGenerationUtil.isExpectedPassword(userInputCode.toCharArray(), salt, code)) {
			log.debug("Code Successfully Validated");
			try {
				if (isExpired(issueTimeStamp)) {
					log.debug("Security code has expired");
					return false;
				}
			} catch (ParseException e) {
				log.error("Error parsing date", e);
				return false;
			}
			log.debug("Security code is valid");
			return true;
		}
		log.debug("Invalid Code");
		return false;

	}

	protected boolean isExpired(String issueTimeStamp) throws ParseException {
		Date createDate = new Date();
		createDate = TimeUtils.decodeGeneralizedTime(issueTimeStamp);
		Date now = new Date();
		long result = now.getTime() / 60000L - createDate.getTime() / 60000L;
		log.debug("Number of minutes since token was generated: " + result);
		return result > Const.TOKEN_DURATION_MINUTES;
	}

	protected GeneratedCode generateCode(JSONObject requestData) {
		PasswordManagementConfiguration conf = new PasswordManagementConfiguration();
		conf.setResetType("Mail");
		conf.setCodeNumberOfCharacters(7);
		return CodeGenerationUtil.getGeneratedCode(conf);
	}

	protected void sendMailCode(JSONObject requestData, String code, String template) throws LDAPException, JSONException {
		log.debug("Starting sendMailCode with code " + code);
		Map<String, String> substitutionMap = new HashMap<String, String>();
		substitutionMap.put("RECEIVER", requestData.getString(Const.EMAIL_ATTRIBUTE_NAME));
		substitutionMap.put("CODE", code);
		EmailHelper emailHelper = new EmailHelper();
		emailHelper.sendEmail(template, requestData.getString(Const.EMAIL_ATTRIBUTE_NAME), true, substitutionMap);
		log.debug("Mail sent");
	}
	
	protected void sendPasswordResetCompleteEmail(JSONObject requestData) throws LDAPException, JSONException {
		log.debug("Starting sendPasswordResetCompleteEmail");
		Map<String, String> substitutionMap = new HashMap<String, String>();
		substitutionMap.put("RECEIVER", requestData.getString(Const.EMAIL_ATTRIBUTE_NAME));
		EmailHelper emailHelper = new EmailHelper();
		emailHelper.sendEmail(Const.MESSAGE_TEMPLATE_PASSWORD_CHANGED, requestData.getString(Const.EMAIL_ATTRIBUTE_NAME), true, substitutionMap);
		log.debug("Mail sent");
	}

	protected void sendResponse(HttpServletResponse resp, JSONObject responseJson, int responseCode) throws IOException {
		resp.setContentType("application/json");
		resp.setStatus(responseCode);
		// Get the printwriter object from response to write the required json
		// object to the output stream
		PrintWriter out = resp.getWriter();
		// Assuming your json object is **jsonObject**, perform the following,
		// it will return your json object
		if (responseJson != null) {
			out.print(responseJson);
		} else {
			out.print("");
		}
		out.flush();
	}

	protected JSONObject getCodeAttributesJson(GeneratedCode generatedCode) {
		Map <String,String> codeAttributes = new HashMap <String,String > ();
		codeAttributes.put(Constants.ATTR_KEY_CODE, generatedCode.getAttributeMap().getSingleValue(Constants.ATTR_KEY_CODE));
		codeAttributes.put(Constants.ATTR_KEY_TIME, generatedCode.getAttributeMap().getSingleValue(Constants.ATTR_KEY_TIME));
		codeAttributes.put(Constants.ATTR_KEY_SALT, generatedCode.getAttributeMap().getSingleValue(Constants.ATTR_KEY_SALT));
		log.debug(codeAttributes.toString());
		JSONObject codeAttributesJson = new JSONObject(codeAttributes);
		return codeAttributesJson;
	}

	protected boolean isOTPValid(JSONObject requestData) throws LDAPException, JSONException {
		log.debug("Starting validateRequest");
		LDAPConnection connection = getLDAPConnection();
		SearchResultEntry result = connection.getEntry(getGlobalIDDn(requestData));
		if (result == null) {
			log.debug("Entry not found");
			return false;
		}
		log.debug("Found entry " + result.toString());
		
		String otp = result.getAttributeValue(Const.CODE);
		if (StringUtils.isEmpty(otp)) {
			log.debug("Stored code empty");
			return false;
		}
		JSONObject storedCodeJSON = new JSONObject(otp);
		log.debug("Stored code " + storedCodeJSON.toString());
		return validateCode(requestData.getString(Const.CODE), storedCodeJSON.getString(Constants.ATTR_KEY_CODE),
				storedCodeJSON.getString(Constants.ATTR_KEY_SALT), storedCodeJSON.getString(Constants.ATTR_KEY_TIME));
	}

	protected boolean userExists(JSONObject requestData) throws LDAPException, JSONException {
		log.debug("Starting userExists");
		LDAPConnection connection = getLDAPConnection();
		SearchResultEntry result = connection.getEntry(getGlobalIDDn(requestData));
		if (result == null) {
			log.debug("User not found, returning false");
			return false;
		}
		log.debug("User found, returning true	");
		return true;
	}
	
	
	public static void main(String[] args) {
		String str = "ou=identities,ou=%dir%,dc=veon,dc=com";
		System.out.print(str.replaceAll("%dir%", "ciao"));
	}

}
