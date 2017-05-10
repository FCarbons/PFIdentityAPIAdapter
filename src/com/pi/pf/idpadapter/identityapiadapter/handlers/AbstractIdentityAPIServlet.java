package com.pi.pf.idpadapter.identityapiadapter.handlers;

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

import com.pi.pf.idpadapter.identityapiadapter.Const;
import com.pi.pf.idpadapter.identityapiadapter.ErrorMessage;
import com.pi.pf.idpadapter.identityapiadapter.IdentityAPIException;
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
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;

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

	protected JSONObject getRequestJSONObject(HttpServletRequest req) throws IdentityAPIException {
		StringBuffer buf = new StringBuffer();
		String line = null;
		try {
			BufferedReader reader = req.getReader();
			while ((line = reader.readLine()) != null)
				buf.append(line);

			log.debug("Raw input: " + buf.toString());
			log.debug("Input JSON " + new JSONObject(buf.toString()));
			return new JSONObject(buf.toString());
		} catch (IOException | JSONException e) {
			log.error(e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.JSON_PARSING_ERROR));
		}
	}

	protected LDAPConnection getLDAPConnection() throws IdentityAPIException {
		if (ldapConnection == null) {
			log.debug("Creating connection to: " + ldapInfo.getHost());
			try {
				ldapConnection = new LDAPConnection(ldapInfo.getHost().split(":")[0], new Integer(ldapInfo.getHost().split(":")[1]).intValue(),
						ldapInfo.getPrincipal(), ldapInfo.getCredentials());
			} catch (LDAPException e) {
				log.error(e);
				throw new IdentityAPIException(new ErrorMessage(ErrorMessage.LDAP_CONNECTION_ERROR));
			}
			log.debug("Connection created");
		}
		return ldapConnection;
	}

	protected String getGlobalIDDn(JSONObject userData) throws IdentityAPIException {
		String baseDN = configuration.getFieldValue(Const.BASE_DN_NAME);
		String mailAddress;
		try {
			mailAddress = userData.getString(Const.EMAIL_ATTRIBUTE_NAME);
			String dn = Const.EMAIL_ATTRIBUTE_NAME + "=" + mailAddress + "," + baseDN.replaceAll("%dir%", "global");
			log.debug("Entry dn " + dn);
			return dn;
		} catch (JSONException e) {
			log.error(e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.MISSING_INPUT_DATA + Const.EMAIL_ATTRIBUTE_NAME));
		}
	}

	protected String getLinkedIDDn(JSONObject userData) throws IdentityAPIException {
		String baseDN = configuration.getFieldValue(Const.BASE_DN_NAME);
		String linkedUID = getAttribute(userData, Const.MOBILE_NUMBER);
		String dn = Const.LINKED_UID + "=" + linkedUID + "," + baseDN.replaceAll("%dir%", getAttribute(userData, Const.COUNTRY).toLowerCase());
		log.debug("Entry dn " + dn);
		return dn;
	}

	protected Collection<Attribute> getAttributeMap(JSONObject userData) {
		Collection<Attribute> set = new HashSet<Attribute>();
		for (String key : JSONObject.getNames(userData)) {
			try {
				set.add(new Attribute(key, userData.get(key).toString()));
			} catch (JSONException e) {
				log.error("Not adding attribute", e);
			}
		}
		return set;
	}

	protected void validateCode(String userInputCode, String generatedHashedCode, String generatedHashedSalt, String issueTimeStamp)
			throws IdentityAPIException {
		byte[] code = DatatypeConverter.parseBase64Binary(generatedHashedCode);
		byte[] salt = DatatypeConverter.parseBase64Binary(generatedHashedSalt);
		if ((userInputCode == null) || (userInputCode.length() == 0)) {
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.MISSING_INPUT_DATA + Const.CODE));
		}
		if (CodeGenerationUtil.isExpectedPassword(userInputCode.toCharArray(), salt, code)) {
			log.debug("Code Successfully Validated");
			try {
				if (isExpired(issueTimeStamp)) {
					log.debug("Security code has expired");
					throw new IdentityAPIException(new ErrorMessage(ErrorMessage.CODE_EXPIRED));
				}
			} catch (ParseException e) {
				log.error("Error parsing date", e);
				throw new IdentityAPIException(new ErrorMessage(ErrorMessage.INTERNAL_ERROR));
			}
			log.debug("Security code is valid");
		} else {
			log.debug("Invalid Code");
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.INVALID_OTP));
		}
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

	protected void sendMailCode(JSONObject requestData, String code, String template) throws IdentityAPIException {
		log.debug("Starting sendMailCode with code " + code);
		String email = getEmail(requestData);
		Map<String, String> substitutionMap = new HashMap<String, String>();
		substitutionMap.put("RECEIVER", email);
		substitutionMap.put("CODE", code);
		EmailHelper emailHelper = new EmailHelper();
		emailHelper.sendEmail(template, email, true, substitutionMap);
		log.debug("Mail sent");
	}

	protected void sendPasswordResetCompleteEmail(JSONObject requestData) throws IdentityAPIException {
		log.debug("Starting sendPasswordResetCompleteEmail");
		String email = getEmail(requestData);
		Map<String, String> substitutionMap = new HashMap<String, String>();
		substitutionMap.put("RECEIVER", email);
		EmailHelper emailHelper = new EmailHelper();
		emailHelper.sendEmail(Const.MESSAGE_TEMPLATE_PASSWORD_CHANGED, email, true, substitutionMap);
		log.debug("Mail sent");
	}

	protected String getEmail(JSONObject requestData) throws IdentityAPIException {
		return getAttribute(requestData, Const.EMAIL_ATTRIBUTE_NAME);
	}

	protected String getAttribute(JSONObject requestData, String attributeName) throws IdentityAPIException {
		try {
			return requestData.getString(attributeName);
		} catch (JSONException e) {
			log.error(e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.MISSING_INPUT_DATA + attributeName));
		}
	}

	protected void sendResponse(HttpServletResponse resp, JSONObject responseJson, int responseCode) {
		resp.setContentType("application/json");
		resp.setStatus(responseCode);
		// Get the printwriter object from response to write the required json
		// object to the output stream
		PrintWriter out;
		try {
			out = resp.getWriter();
			// Assuming your json object is **jsonObject**, perform the
			// following,
			// it will return your json object
			if (responseJson != null) {
				out.print(responseJson);
			} else {
				out.print("");
			}
			out.flush();
		} catch (IOException e) {
			log.error(e);
		}

	}

	protected void sendResponse(HttpServletResponse resp, ErrorMessage message) {
		sendResponse(resp, message.toJsonObject(), HttpServletResponse.SC_OK);
	}

	protected JSONObject getCodeAttributesJson(GeneratedCode generatedCode) {
		Map<String, String> codeAttributes = new HashMap<String, String>();
		codeAttributes.put(Constants.ATTR_KEY_CODE, generatedCode.getAttributeMap().getSingleValue(Constants.ATTR_KEY_CODE));
		codeAttributes.put(Constants.ATTR_KEY_TIME, generatedCode.getAttributeMap().getSingleValue(Constants.ATTR_KEY_TIME));
		codeAttributes.put(Constants.ATTR_KEY_SALT, generatedCode.getAttributeMap().getSingleValue(Constants.ATTR_KEY_SALT));
		log.debug(codeAttributes.toString());
		JSONObject codeAttributesJson = new JSONObject(codeAttributes);
		return codeAttributesJson;
	}

	protected void validateOTP(JSONObject requestData, SearchResultEntry result) throws IdentityAPIException {
		log.debug("Starting validateOTP");

		String otp = result.getAttributeValue(Const.CODE);
		if (StringUtils.isEmpty(otp)) {
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.INVALID_OTP));
		}

		try {
			JSONObject storedCodeJSON = new JSONObject(otp);
			log.debug("Stored code " + storedCodeJSON.toString());
			validateCode(requestData.getString(Const.CODE), storedCodeJSON.getString(Constants.ATTR_KEY_CODE),
					storedCodeJSON.getString(Constants.ATTR_KEY_SALT), storedCodeJSON.getString(Constants.ATTR_KEY_TIME));
		} catch (JSONException e) {
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.INVALID_OTP));
		}
	}
	
	

	protected SearchResultEntry getGlobalIdentityByGlobalID(JSONObject requestData) throws IdentityAPIException {
		LDAPConnection connection = getLDAPConnection();
		String globalUID = "";
		try {
			globalUID = requestData.getString(Const.GLOBAL_UID);
		} catch (JSONException e1) {
			log.error(e1);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.MISSING_INPUT_DATA));
		}

		String baseDN = configuration.getFieldValue(Const.BASE_DN_NAME).replaceAll("%dir%", "global");
		String filter = "(" + Const.GLOBAL_UID + "=" + globalUID + ")";
		log.debug("Serach: " + baseDN + " - " + filter);
		try {
			SearchResult searchResult = connection.search(baseDN, SearchScope.SUB, filter);
			if (searchResult.getEntryCount() == 0) {
				throw new IdentityAPIException(new ErrorMessage(ErrorMessage.IDENTITY_NOT_FOUND));
			}
			log.debug("Found entry " + searchResult.getSearchEntries().get(0));
			return searchResult.getSearchEntries().get(0);
		} catch (LDAPException e) {
			log.error(e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.GENERIC_LDAP_ERROR));
		}
	}

	protected SearchResultEntry getGlobalIdentity(JSONObject requestData) throws IdentityAPIException {
		log.debug("Starting getGlobalIdentity");
		LDAPConnection connection = getLDAPConnection();
		SearchResultEntry result;

		try {
			result = connection.getEntry(getGlobalIDDn(requestData));
			log.debug("Result " + result);
		} catch (LDAPException e) {
			log.error(e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.GENERIC_LDAP_ERROR));
		}
		if (result == null) {
			log.error("Entry not found, throwing exception");
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.IDENTITY_NOT_FOUND));
		}
		log.debug("Found entry " + result.toString());
		return result;
	}

	protected boolean userExistsByEmail(JSONObject requestData) {
		log.debug("Starting userExists");
		try {
			getGlobalIdentity(requestData);
		} catch (IdentityAPIException e) {
			log.debug("User not found, returning false");
			return false;
		}
		log.debug("User found, returning true");
		return true;
	}

	protected JSONObject getSuccessResponseJSON() {
		JSONObject result = new JSONObject();
		try {
			result.put(Const.RESULT, Const.SUCCESS);
		} catch (JSONException e) {
			log.error(e);
		}
		return result;
	}

	protected void mandadoryFieldsExist(JSONObject request, String[] mandatoryFieldNames) throws IdentityAPIException {
		for (String fieldName : mandatoryFieldNames) {
			getAttribute(request, fieldName);
		}
		log.debug("Mandatory fields exist");
	}

	public static void main(String[] args) {
		
	}

	
	
}
