package com.pi.pf.idpadapter.identityapiadapter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.websso.servlet.adapter.Handler;

import com.pingidentity.adapters.htmlform.pwdreset.common.Constants;
import com.pingidentity.adapters.htmlform.pwdreset.model.GeneratedCode;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.SearchResultEntry;

public class ValidationServlet extends AbstractIdentityAPIServlet implements Handler {

	
	private static final long serialVersionUID = 1L;
	final Log log = LogFactory.getLog(this.getClass());
	
	public ValidationServlet(Configuration configuration) {
		super(configuration);
		log.debug("Creating RegistrationServlet " + configuration);
	}

	@Override
	public void handle(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.debug("*** Starting handle");

		try {
			JSONObject request = getRequestJSONObject(req);
			if (validateRequest(request)) {
				GeneratedCode generatedCode = generateCode (request);
				updateCode(request, generatedCode);
				sendMailCode(request,generatedCode.getCode());
				sendResponse(resp, null, HttpServletResponse.SC_CREATED);
			} else {
				sendResponse(resp, null, HttpServletResponse.SC_BAD_REQUEST);
			}
		} catch (Exception e) {
			sendResponse(resp, null, HttpServletResponse.SC_BAD_REQUEST);
			log.error("Error creating the new identity", e);
		}
		log.debug("*** Exiting handle");
	}
	
	private boolean validateRequest(JSONObject requestData) throws LDAPException, JSONException {
		log.debug("Starting validateRequest");
		LDAPConnection connection = getLDAPConnection();
		SearchResultEntry result = connection.getEntry(getDn(requestData));
		if (result == null || !result.getAttributeValue(Const.STATUS).equalsIgnoreCase(Const.REGISTERED)) {
			return false;
		}
		return true;
	}
	
	private void updateCode(JSONObject requestData,GeneratedCode generatedCode) throws LDAPException, JSONException {
		log.debug("Starting updateCode");
		LDAPConnection connection = getLDAPConnection();
		JSONObject codeAttributesJson = getCodeAttributesJson(generatedCode);
		Modification mod = new Modification(ModificationType.REPLACE, Const.CODE,codeAttributesJson.toString());
		connection.modify(getDn(requestData), mod);
		log.debug("Exiting updateCode");
	}

	public static void main(String[] args) {
		Map <String,String> codeAttributes = new HashMap <String,String > ();
		codeAttributes.put(Constants.ATTR_KEY_CODE, "A");
		codeAttributes.put(Constants.ATTR_KEY_TIME, "B");
		JSONObject codeAttributesJson = new JSONObject(codeAttributes);
		System.out.println(codeAttributesJson.toString());
	}
}
