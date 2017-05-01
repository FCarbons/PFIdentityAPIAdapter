package com.pi.pf.idpadapter.identityapiadapter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.websso.servlet.adapter.Handler;

import com.pingidentity.adapters.htmlform.pwdreset.model.GeneratedCode;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.SearchResultEntry;

/**
 * Initiates a password reset, sending an OTP to the user and 
 *
 */
public class InitiatePasswordResetServlet extends AbstractIdentityAPIServlet implements Handler {

	private static final long serialVersionUID = 1L;
	final Log log = LogFactory.getLog(this.getClass());

	public InitiatePasswordResetServlet(Configuration configuration) {
		super(configuration);
		log.debug("Creating RegistrationServlet " + configuration);
	}

	@Override
	public void handle(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.debug("*** Starting handle");

		try {
			JSONObject request = getRequestJSONObject(req);
			if (userExists(request)) {
				GeneratedCode generatedCode = generateCode(request);
				updateCodeAndStatus(request, generatedCode);
				sendMailCode(request, generatedCode.getCode());
			}
			// always send the same response (even if record does not exist or is in the wrong state)
			sendResponse(resp, null, HttpServletResponse.SC_CREATED);
		} catch (Exception e) {
			sendResponse(resp, null, HttpServletResponse.SC_BAD_REQUEST);
			log.error("Error creating the new identity", e);
		}
		log.debug("*** Exiting handle");
	}

	private boolean userExists (JSONObject requestData) throws LDAPException, JSONException {
		log.debug("Starting isRegistered");
		LDAPConnection connection = getLDAPConnection();
		SearchResultEntry result = connection.getEntry(getDn(requestData));
		if (result == null) {
			return false;
		}
		return true;
	}

	private void updateCodeAndStatus(JSONObject requestData, GeneratedCode generatedCode) throws LDAPException, JSONException {
		log.debug("Starting updateCode");
		LDAPConnection connection = getLDAPConnection();
		JSONObject codeAttributesJson = getCodeAttributesJson(generatedCode);
		
		List<Modification> mods = new ArrayList<Modification>();
		mods.add(new Modification(ModificationType.REPLACE, Const.STATUS, Const.PASSWORD_CHANGE));
		mods.add(new Modification(ModificationType.REPLACE, Const.CODE, codeAttributesJson.toString()));
		
		connection.modify(getDn(requestData), mods);
		log.debug("Exiting updateCode");
	}

	public static void main(String[] args) {
	}
}
