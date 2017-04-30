package com.pi.pf.idpadapter.identityapiadapter;

import java.io.IOException;

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
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.SearchResultEntry;

public class PaswordResetServlet extends AbstractIdentityAPIServlet implements Handler {

	private static final long serialVersionUID = 1L;
	private final Log log = LogFactory.getLog(this.getClass());

	public PaswordResetServlet(Configuration configuration) {
		super(configuration);
		log.debug("Creating ActivationServlet " + configuration);
	}

	@Override
	public void handle(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.debug("*** Starting handle");

		try {
			JSONObject activationReqeust = getRequestJSONObject(req);
			if (validateRequest(activationReqeust)) {
				activateIdentity(activationReqeust);
				sendResponse(resp, null, HttpServletResponse.SC_CREATED);
			} else {
				sendResponse(resp, null, HttpServletResponse.SC_BAD_REQUEST);
			}
			
		} catch (Exception e) {
			sendResponse(resp, null, HttpServletResponse.SC_BAD_REQUEST);
			log.error("Error activating the identity", e);
		}
		log.debug("*** Exiting handle");
	}

	private void activateIdentity(JSONObject requestData) throws LDAPException, JSONException {
		log.debug("Starting activateIdentity");
		LDAPConnection connection = getLDAPConnection();
		Modification mod = new Modification(ModificationType.REPLACE, Const.STATUS, Const.ACTIVE);
		connection.modify(getDn(requestData), mod);
		log.debug("Identity activated");
	}

	private boolean validateRequest(JSONObject requestData) throws LDAPException, JSONException {
		log.debug("Starting validateRequest");
		LDAPConnection connection = getLDAPConnection();
		SearchResultEntry result = connection.getEntry(getDn(requestData));
		log.debug("Found entry " + result.toString());
		JSONObject storedCodeJSON = new JSONObject(result.getAttributeValue(Const.CODE));
		log.debug("Stored code " + storedCodeJSON.toString());
		return validateCode(requestData.getString(Const.CODE), storedCodeJSON.getString(Constants.ATTR_KEY_CODE),
				storedCodeJSON.getString(Constants.ATTR_KEY_SALT), storedCodeJSON.getString(Constants.ATTR_KEY_TIME));
	}

	public static void main(String[] args) {
		
	}
}
