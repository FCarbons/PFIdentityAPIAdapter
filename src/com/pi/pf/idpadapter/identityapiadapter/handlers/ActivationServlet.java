package com.pi.pf.idpadapter.identityapiadapter.handlers;

import java.io.IOException;

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
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.SearchResultEntry;

public class ActivationServlet extends AbstractIdentityAPIServlet implements Handler {

	private String[] mandatoryFields = { Const.GLOBAL_UID, Const.CODE };

	private static final long serialVersionUID = 1L;
	final Log log = LogFactory.getLog(this.getClass());

	public ActivationServlet(Configuration configuration) {
		super(configuration);
		log.debug("Creating ActivationServlet " + configuration);
	}

	@Override
	public void handle(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.debug("*** Starting handle");

		try {
			JSONObject request = getRequestJSONObject(req);
			mandadoryFieldsExist(request, mandatoryFields);
			validateOTP(request,getGlobalIdentityByGlobalID(request));
			activateIdentity(request);
			deleteOTP (request);
			sendResponse(resp, getSuccessResponseJSON(), HttpServletResponse.SC_OK);
		} catch (IdentityAPIException e) {
			log.error(e);
			sendResponse(resp, e.getError());
		}
		log.debug("*** Exiting handle");
	}

	protected void deleteOTP(JSONObject request) throws IdentityAPIException {
		log.debug("Starting activateIdentity");
		SearchResultEntry result  = getGlobalIdentityByGlobalID (request);
		LDAPConnection connection = getLDAPConnection();
		Modification mod = new Modification(ModificationType.DELETE, Const.CODE);
		try {
			connection.modify(result.getDN(), mod);
			log.debug("Token deleted");
		} catch (LDAPException e) {
			log.error(e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.GENERIC_LDAP_ERROR));
		}
	}

	private void activateIdentity(JSONObject requestData) throws IdentityAPIException {
		log.debug("Starting activateIdentity");
		SearchResultEntry result  = getGlobalIdentityByGlobalID (requestData);
		String status = result.getAttribute(Const.STATUS).getValue();
		if (!status.equalsIgnoreCase(Const.REGISTERED)) {
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.NOT_REGISTERED_STATE));
		}
		LDAPConnection connection = getLDAPConnection();
		Modification mod = new Modification(ModificationType.REPLACE, Const.STATUS, Const.ACTIVE);
		try {
			connection.modify(result.getDN(), mod);
			log.debug("Identity activated");
		} catch (LDAPException e) {
			log.error(e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.GENERIC_LDAP_ERROR));
		}
	}
	
}
