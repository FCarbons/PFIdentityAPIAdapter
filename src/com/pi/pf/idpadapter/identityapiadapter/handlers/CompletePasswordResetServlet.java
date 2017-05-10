package com.pi.pf.idpadapter.identityapiadapter.handlers;

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

import com.pi.pf.idpadapter.identityapiadapter.Const;
import com.pi.pf.idpadapter.identityapiadapter.ErrorMessage;
import com.pi.pf.idpadapter.identityapiadapter.IdentityAPIException;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.SearchResultEntry;

/**
 * Completes a password reset, receiving email, otp and new password.
 * 
 */
public class CompletePasswordResetServlet extends AbstractIdentityAPIServlet implements Handler {
	
	private String[] mandatoryFields = { Const.EMAIL_ATTRIBUTE_NAME, Const.USER_PASSWORD, Const.CODE };
	
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
			mandadoryFieldsExist(requestJson, mandatoryFields);
			validateOTP(requestJson, getGlobalIdentity(requestJson));
			resetPassword(requestJson);
			sendPasswordResetCompleteEmail(requestJson);
			sendResponse(resp, getSuccessResponseJSON(), HttpServletResponse.SC_OK);
		} catch (IdentityAPIException e) {
			sendResponse(resp, e.getError());
			log.error("Error activating the identity", e);
		}
		log.debug("*** Exiting handle");
	}

	private void resetPassword(JSONObject requestData) throws IdentityAPIException {
		log.debug("Starting resetPassword");
		String password;
		try {
			password = requestData.getString(Const.USER_PASSWORD);
		} catch (JSONException e1) {
			log.error (e1);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.MISSING_INPUT_DATA));
		}
		LDAPConnection connection = getLDAPConnection();
		List<Modification> mods = new ArrayList<Modification>();
		mods.add(new Modification(ModificationType.REPLACE, Const.STATUS, Const.ACTIVE));
		mods.add(new Modification(ModificationType.REPLACE, Const.USER_PASSWORD, password));
		try {
			connection.modify(getGlobalIDDn(requestData), mods);
			log.debug("Password reset");
		} catch (LDAPException e) {
			log.error(e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.GENERIC_LDAP_ERROR));
		}
	}

	public static void main(String[] args) {

	}
}
