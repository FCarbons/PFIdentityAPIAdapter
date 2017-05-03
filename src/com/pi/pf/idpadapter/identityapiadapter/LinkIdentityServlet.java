package com.pi.pf.idpadapter.identityapiadapter;

import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.UUID;

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

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;

public class LinkIdentityServlet extends AbstractIdentityAPIServlet implements Handler {

	private static final long serialVersionUID = 1L;
	final Log log = LogFactory.getLog(this.getClass());

	public LinkIdentityServlet(Configuration configuration) {
		super(configuration);
		log.debug("Creating LinkIdentityServlet " + configuration);
	}

	@Override
	public void handle(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.debug("*** Starting handle");
		
		String emailFromHeader = req.getHeader(Const.EMAIL_ATTRIBUTE_NAME);
		String globalUIDFromHeader = req.getHeader(Const.GLOBAL_UID);
		
		if (StringUtils.isEmpty(emailFromHeader) || StringUtils.isEmpty(globalUIDFromHeader)) {
			log.debug("Email or globalUID header empty, returning error");
			sendResponse(resp, null, HttpServletResponse.SC_BAD_REQUEST);
			return;
		}
		
		try {
			JSONObject request = getRequestJSONObject(req);
			request.put(Const.EMAIL_ATTRIBUTE_NAME, emailFromHeader);
			request.put(Const.GLOBAL_UID,globalUIDFromHeader);
			log.debug("Request after headers injection: " + request.toString());
			if (userExists(request)) {
				linkIdentity (request);
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

	

	private void linkIdentity(JSONObject request) throws JSONException, LDAPException {
		log.debug("Starting linkIdentity");
		LDAPConnection connection = getLDAPConnection();
		Collection<Attribute> set = getLDAPAttributeSet(request);
		connection.add(getLinkedIDDn(request), set);
//		JSONObject responseJson = new JSONObject(requestData, JSONObject.getNames(requestData));
//		responseJson.remove(Const.USER_PASSWORD);
//		responseJson.put(Const.GLOBAL_UID, globalUID);
//		log.debug("Exiting registerIdentity with " + responseJson.toString());
		
	}

	private Collection<Attribute> getLDAPAttributeSet(JSONObject requestData) throws JSONException {
		Collection<Attribute> set = new HashSet<Attribute> ();
		set.add(new Attribute("objectClass", "top"));
		set.add(new Attribute("objectClass", Const.LINKED_ID_OBJECTCLASS));
		set.add(new Attribute(Const.GLOBAL_UID, requestData.getString(Const.GLOBAL_UID)));
		set.add(new Attribute(Const.LINKED_UID, requestData.getString(Const.MOBILE_NUMBER)));
		set.add(new Attribute(Const.TOKEN, "test"));
		return set;
	}
}
