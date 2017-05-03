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

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;

/**
 * Completes a password reset, receiving email, otp and new password.
 * 
 */
public class CompletePasswordResetServlet extends AbstractIdentityAPIServlet implements Handler {

	private static final long serialVersionUID = 1L;
	private final Log log = LogFactory.getLog(this.getClass());

	public CompletePasswordResetServlet(Configuration configuration) {
		super(configuration);
		log.debug("Creating CompletePasswordResetServlet " + configuration);
	}

	@Override
	public void handle(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.debug("*** Starting handle");

		try {
			JSONObject requestJson = getRequestJSONObject(req);
			if (isOTPValid(requestJson)) {
				resetPassword(requestJson);
				sendPasswordResetCompleteEmail(requestJson);
			}
			sendResponse(resp, null, HttpServletResponse.SC_CREATED);
		} catch (Exception e) {
			sendResponse(resp, null, HttpServletResponse.SC_BAD_REQUEST);
			log.error("Error activating the identity", e);
		}
		log.debug("*** Exiting handle");
	}

	private void resetPassword(JSONObject requestData) throws LDAPException, JSONException {
		log.debug("Starting activateIdentity");
		LDAPConnection connection = getLDAPConnection();
		List<Modification> mods = new ArrayList<Modification>();
		mods.add(new Modification(ModificationType.REPLACE, Const.STATUS, Const.ACTIVE));
		mods.add(new Modification(ModificationType.REPLACE, Const.USER_PASSWORD, requestData.getString(Const.USER_PASSWORD)));
		connection.modify(getGlobalIDDn(requestData), mods);
		log.debug("Password reset");
	}

	public static void main(String[] args) {

	}
}
