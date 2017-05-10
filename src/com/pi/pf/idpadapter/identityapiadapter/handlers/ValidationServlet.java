package com.pi.pf.idpadapter.identityapiadapter.handlers;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.websso.servlet.adapter.Handler;

import com.pi.pf.idpadapter.identityapiadapter.Const;
import com.pi.pf.idpadapter.identityapiadapter.ErrorMessage;
import com.pi.pf.idpadapter.identityapiadapter.IdentityAPIException;
import com.pingidentity.adapters.htmlform.pwdreset.common.Constants;
import com.pingidentity.adapters.htmlform.pwdreset.model.GeneratedCode;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.SearchResultEntry;

/**
 * Resends the OTP to a previously registered email address.
 */
public class ValidationServlet extends AbstractIdentityAPIServlet implements Handler {
	
	private String[] mandatoryFields = { Const.EMAIL_ATTRIBUTE_NAME };
	
	private static final long serialVersionUID = 1L;
	final Log log = LogFactory.getLog(this.getClass());

	public ValidationServlet(Configuration configuration) {
		super(configuration);
		log.debug("Creating ValidationServlet " + configuration);
	}

	@Override
	public void handle(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.debug("*** Starting handle");

		try {
			JSONObject request = getRequestJSONObject(req);
			mandadoryFieldsExist(request, mandatoryFields);
			if (isRegistered(request)) {
				GeneratedCode generatedCode = generateCode(request);
				updateCode(request, generatedCode);
				sendMailCode(request, generatedCode.getCode(),Const.MESSAGE_TEMPLATE_REGISTRATION_HTML);
			}
			// always send the same response (even if record does not exist or is in the wrong state)
			sendResponse(resp, getSuccessResponseJSON(), HttpServletResponse.SC_OK);
		} catch (IdentityAPIException e) {
			log.error(e);
			sendResponse(resp, e.getError());
		}
		log.debug("*** Exiting handle");
	}

	private boolean isRegistered(JSONObject requestData) throws IdentityAPIException{
		log.debug("Starting isRegistered");
		LDAPConnection connection = getLDAPConnection();
		SearchResultEntry result;
		try {
			result = connection.getEntry(getGlobalIDDn(requestData));
		} catch (LDAPException e) {
			log.error(e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.GENERIC_LDAP_ERROR));
		}
		if (result == null || !result.getAttributeValue(Const.STATUS).equalsIgnoreCase(Const.REGISTERED)) {
			log.debug("User not in status not registered or null");
			return false;
		}
		log.debug("User not in status not registered");
		return true;
	}

	private void updateCode(JSONObject requestData, GeneratedCode generatedCode) throws IdentityAPIException {
		log.debug("Starting updateCode");
		LDAPConnection connection = getLDAPConnection();
		JSONObject codeAttributesJson = getCodeAttributesJson(generatedCode);
		Modification mod = new Modification(ModificationType.REPLACE, Const.CODE, codeAttributesJson.toString());
		try {
			connection.modify(getGlobalIDDn(requestData), mod);
		} catch (LDAPException e) {
			log.error(e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.GENERIC_LDAP_ERROR));
		}
		log.debug("Exiting updateCode");
	}

	public static void main(String[] args) {
		Map<String, String> codeAttributes = new HashMap<String, String>();
		codeAttributes.put(Constants.ATTR_KEY_CODE, "A");
		codeAttributes.put(Constants.ATTR_KEY_TIME, "B");
		JSONObject codeAttributesJson = new JSONObject(codeAttributes);
		System.out.println(codeAttributesJson.toString());
	}
}
