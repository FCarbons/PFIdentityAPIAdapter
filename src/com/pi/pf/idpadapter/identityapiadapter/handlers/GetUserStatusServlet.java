package com.pi.pf.idpadapter.identityapiadapter.handlers;

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

import com.pi.pf.idpadapter.identityapiadapter.Const;
import com.pi.pf.idpadapter.identityapiadapter.ErrorMessage;
import com.pi.pf.idpadapter.identityapiadapter.IdentityAPIException;
import com.unboundid.ldap.sdk.SearchResultEntry;

/**
 * Get the status of a user.
 *
 */
public class GetUserStatusServlet extends AbstractIdentityAPIServlet implements Handler {

	private String[] mandatoryFields = { Const.EMAIL_ATTRIBUTE_NAME };

	private static final long serialVersionUID = 1L;
	final Log log = LogFactory.getLog(this.getClass());

	public GetUserStatusServlet(Configuration configuration) {
		super(configuration);
		log.debug("Creating InitiatePasswordResetServlet " + configuration);
	}

	@Override
	public void handle(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.debug("*** Starting handle");

		try {
			JSONObject request = getRequestJSONObject(req);
			mandadoryFieldsExist(request, mandatoryFields);

			if (!userExistsByEmail(request)) {
				throw new IdentityAPIException(new ErrorMessage(ErrorMessage.IDENTITY_NOT_FOUND));
			}

			sendResponse(resp, getUserStatus(request), HttpServletResponse.SC_OK);
		} catch (IdentityAPIException e) {
			log.error(e);
			sendResponse(resp, e.getError());
		}
		log.debug("*** Exiting handle");
	}

	private JSONObject getUserStatus(JSONObject requestData) throws IdentityAPIException {
		log.debug("Starting getUserStatus");
		JSONObject requestResult = getSuccessResponseJSON();
		SearchResultEntry result = getGlobalIdentity(requestData);
		String status = result.getAttribute(Const.STATUS).getValue();
		String globalUID = result.getAttributeValue(Const.GLOBAL_UID);
		try {
			requestResult.put(Const.STATUS, status);
			requestResult.put(Const.GLOBAL_UID, globalUID);
		} catch (JSONException e) {
			log.error(e);
		}
		log.debug("Leaving getUserStatus");
		return requestResult;
	}

	public static void main(String[] args) {
	}
}
