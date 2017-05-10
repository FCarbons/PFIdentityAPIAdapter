package com.pi.pf.idpadapter.identityapiadapter.handlers;

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

import com.pi.pf.idpadapter.identityapiadapter.Const;
import com.pi.pf.idpadapter.identityapiadapter.ErrorMessage;
import com.pi.pf.idpadapter.identityapiadapter.IdentityAPIException;
import com.pingidentity.adapters.htmlform.pwdreset.model.GeneratedCode;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;

public class RegistrationServlet extends AbstractIdentityAPIServlet implements Handler {

	private String[] mandatoryFields = { Const.EMAIL_ATTRIBUTE_NAME, Const.USER_PASSWORD };

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
			JSONObject request = getRequestJSONObject(req);
			mandadoryFieldsExist(request, mandatoryFields);
			GeneratedCode generatedCode = generateCode(request);
			JSONObject responseJson = registerIdentity(request, generatedCode);
			sendMailCode(request, generatedCode.getCode(), Const.MESSAGE_TEMPLATE_REGISTRATION_HTML);
			sendResponse(resp, responseJson, HttpServletResponse.SC_OK);
		} catch (IdentityAPIException e) {
			log.error(e);
			sendResponse(resp, e.getError());
		} catch (Exception e) {
			log.error(e);
			sendResponse(resp, new ErrorMessage(ErrorMessage.INTERNAL_ERROR));
		}
		log.debug("*** Exiting handle");
	}

	private JSONObject registerIdentity(JSONObject requestData, GeneratedCode generatedCode) throws IdentityAPIException {
		log.debug("Starting registerIdentity");
		String globalUID = UUID.randomUUID().toString();
		JSONObject codeAttributesJson = getCodeAttributesJson(generatedCode);
		LDAPConnection connection = getLDAPConnection();
		Collection<Attribute> set = getLDAPAttributeSet(globalUID, requestData, codeAttributesJson);
		if (userExistsByEmail(requestData)) {
			log.debug("User already exists, throwing IdentityAPIException");
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.USER_ALREADY_EXISTS));
		}
		try {
			connection.add(getGlobalIDDn(requestData), set);
		} catch (LDAPException e) {
			log.error(e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.GENERIC_LDAP_ERROR));
		}

		// JSONObject responseJson = new JSONObject(requestData,
		// JSONObject.getNames(requestData));
		try {
			JSONObject responseJson = new JSONObject();
			responseJson.put(Const.RESULT, Const.SUCCESS);
			responseJson.put(Const.GLOBAL_UID, globalUID);
			log.debug("Exiting registerIdentity with " + responseJson.toString());
			return responseJson;
		} catch (JSONException e) {
			log.error(e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.INTERNAL_ERROR));
		}

	}

	private Collection<Attribute> getLDAPAttributeSet(String globalUID, JSONObject requestData, JSONObject codeAttributesJson) {
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
