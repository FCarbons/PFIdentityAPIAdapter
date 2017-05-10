package com.pi.pf.idpadapter.identityapiadapter.handlers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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
import com.pingidentity.adapters.htmlform.pwdreset.model.GeneratedCode;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;

/**
 * Initiates a password reset, sending an OTP to the user and 
 *
 */
public class InitiatePasswordResetServlet extends AbstractIdentityAPIServlet implements Handler {
	
	
	private String[] mandatoryFields = { Const.EMAIL_ATTRIBUTE_NAME };
	
	private static final long serialVersionUID = 1L;
	final Log log = LogFactory.getLog(this.getClass());

	public InitiatePasswordResetServlet(Configuration configuration) {
		super(configuration);
		log.debug("Creating InitiatePasswordResetServlet " + configuration);
	}

	@Override
	public void handle(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.debug("*** Starting handle");

		try {
			JSONObject request = getRequestJSONObject(req);
			mandadoryFieldsExist(request, mandatoryFields);
			if (userExistsByEmail(request)) {
				GeneratedCode generatedCode = generateCode(request);
				updateCodeAndStatus(request, generatedCode);
				sendMailCode(request, generatedCode.getCode(),Const.MESSAGE_TEMPLATE_PASSWORD_RESET_HTML);
			}
			// always send the same response (even if record does not exist or is in the wrong state)
			sendResponse(resp, getSuccessResponseJSON(), HttpServletResponse.SC_OK);
		} catch (IdentityAPIException e) {
			log.error(e);
			sendResponse(resp,e.getError());
		}
		log.debug("*** Exiting handle");
	}

	private void updateCodeAndStatus(JSONObject requestData, GeneratedCode generatedCode) throws IdentityAPIException {
		log.debug("Starting updateCode");
		LDAPConnection connection = getLDAPConnection();
		JSONObject codeAttributesJson = getCodeAttributesJson(generatedCode);
		
		List<Modification> mods = new ArrayList<Modification>();
		mods.add(new Modification(ModificationType.REPLACE, Const.STATUS, Const.PASSWORD_CHANGE));
		mods.add(new Modification(ModificationType.REPLACE, Const.CODE, codeAttributesJson.toString()));
		
		try {
			connection.modify(getGlobalIDDn(requestData), mods);
		} catch (LDAPException e) {
			log.error(e);
			throw new IdentityAPIException(new ErrorMessage(ErrorMessage.GENERIC_LDAP_ERROR));
		}
		log.debug("Exiting updateCode");
	}

	public static void main(String[] args) {
	}
}
