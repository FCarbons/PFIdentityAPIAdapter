package com.pi.pf.idpadapter.identityapiadapter;

import java.io.IOException;
import java.util.Collection;
import java.util.UUID;

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
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;

public class RegistrationServlet extends AbstractIdentityAPIServlet implements Handler {

	
	private static final long serialVersionUID = 1L;
	final Log log = LogFactory.getLog(this.getClass());
	
	public RegistrationServlet(Configuration configuration) {
		super(configuration);
		log.debug("Creating RegistrationServlet " + configuration);
	}

	@Override
	public void handle(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.debug("*** Starting handle");

		try {
			JSONObject registrationRequest = getRequestJSONObject(req);
			GeneratedCode generatedCode = generateCode (registrationRequest);
			JSONObject responseJson = registerIdentity(registrationRequest,generatedCode);
			sendMailCode(registrationRequest,generatedCode.getCode());
			sendResponse(resp, responseJson, HttpServletResponse.SC_CREATED);
		} catch (Exception e) {
			sendResponse(resp, null, HttpServletResponse.SC_BAD_REQUEST);
			log.error("Error creating the new identity", e);
		}
		log.debug("*** Exiting handle");
	}

	private JSONObject registerIdentity(JSONObject requestData,GeneratedCode generatedCode) throws LDAPException, JSONException {
		log.debug("Starting registerIdentity");
		String globalUID = UUID.randomUUID().toString ();
		JSONObject codeAttributesJson = getCodeAttributesJson(generatedCode);
		LDAPConnection connection = getLDAPConnection();
		Collection<Attribute> set = getLDAPAttributeSet(globalUID, requestData, codeAttributesJson);
		connection.add(getDn(requestData), set);
		
		JSONObject responseJson = new JSONObject(requestData, JSONObject.getNames(requestData));
		responseJson.remove(Const.USER_PASSWORD);
		responseJson.put(Const.GLOBAL_UID, globalUID);
		log.debug("Exiting registerIdentity with " + responseJson.toString());
		return responseJson;
	}

	private Collection<Attribute> getLDAPAttributeSet(String globalUID, JSONObject requestData, JSONObject codeAttributesJson) throws JSONException {
		Collection<Attribute> set = getAttributeMap(requestData);
		set.add(new Attribute("objectClass", "top"));
		set.add(new Attribute("objectClass", configuration.getFieldValue(Const.OBJECT_CLASS_NAME)));
		set.add(new Attribute(Const.STATUS, Const.REGISTERED));
		set.add(new Attribute(Const.GLOBAL_UID, globalUID));
		set.add(new Attribute(Const.CODE, codeAttributesJson.toString()));
		return set;
	}

	public static void main(String[] args) {
		
	}
}
