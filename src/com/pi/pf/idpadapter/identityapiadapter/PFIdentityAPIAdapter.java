package com.pi.pf.idpadapter.identityapiadapter;

import java.io.IOException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.AuthnAdapterException;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.gui.LdapDatastoreFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthenticationAdapter;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthnAdapterDescriptor;
import org.sourceid.saml20.adapter.state.SessionStateSupport;
import org.sourceid.saml20.adapter.state.TransactionalStateSupport;
import org.sourceid.websso.bindings.FormPost;
import org.sourceid.websso.servlet.adapter.HandlerRegistry;

import com.pi.pf.idpadapter.identityapiadapter.handlers.ActivationServlet;
import com.pi.pf.idpadapter.identityapiadapter.handlers.CompletePasswordResetServlet;
import com.pi.pf.idpadapter.identityapiadapter.handlers.GetUserStatusServlet;
import com.pi.pf.idpadapter.identityapiadapter.handlers.InitiatePasswordResetServlet;
import com.pi.pf.idpadapter.identityapiadapter.handlers.LinkIdentityServlet;
import com.pi.pf.idpadapter.identityapiadapter.handlers.RegistrationServlet;
import com.pi.pf.idpadapter.identityapiadapter.handlers.ValidationServlet;
import com.pingidentity.sdk.AuthnAdapterResponse;
import com.pingidentity.sdk.AuthnAdapterResponse.AUTHN_STATUS;
import com.pingidentity.sdk.IdpAuthenticationAdapterV2;
import com.pingidentity.sdk.oauth20.AccessTokenIssuer;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;

/**
 * <p>
 * Redirects the user to an external application with a JWT token (used to pass
 * control to an external app in the authentication chain).
 * </p>
 */
public class PFIdentityAPIAdapter implements IdpAuthenticationAdapterV2 {

	
	private final Log log = LogFactory.getLog(this.getClass());

	private IdpAuthnAdapterDescriptor descriptor;

	public PFIdentityAPIAdapter() {
		log.debug("Creating PFIdentityAPIAdapter");
		// Create a GUI descriptor
		AdapterConfigurationGuiDescriptor guiDescriptor = new AdapterConfigurationGuiDescriptor("Identity API adapter descriptor");

//		TextFieldDescriptor oauthClientAttributeField = new TextFieldDescriptor(ATTR_OAUTH_CLIENT_NAME, ATTR_OAUTH_CLIENT_LABEL);
//
//		TextFieldDescriptor oauthScopesAttributeField = new TextFieldDescriptor(ATTR_OAUTH_SCOPES_NAME, ATTR_OAUTH_SCOPES_LABEL);
//
//		TextFieldDescriptor accessTokenManagerAttributeField = new TextFieldDescriptor(ATTR_ACCESS_TOKEN_MANAGER_NAME, ATTR_ACCESS_TOKEN_MANAGER_LABEL);
//
//		TextFieldDescriptor externalAppUrlAttributeField = new TextFieldDescriptor(ATTR_EXTERNAL_APP_URL_NAME, ATTR_EXTERNAL_APP_URL_LABEL);
		
		LdapDatastoreFieldDescriptor ldapDatastoreFieldDescriptor = new LdapDatastoreFieldDescriptor(Const.LDAP_DATASOURCE_NAME, Const.LDAP_DATASOURCE_LABEL);
		TextFieldDescriptor baseDNAttributeField = new TextFieldDescriptor(Const.BASE_DN_NAME, Const.BASE_DN_LABEL);
		TextFieldDescriptor objectClassAttributeField = new TextFieldDescriptor(Const.OBJECT_CLASS_NAME, Const.OBJECT_CLASS_LABEL);
		
//		guiDescriptor.addField(oauthClientAttributeField);
//		guiDescriptor.addField(oauthScopesAttributeField);
//		guiDescriptor.addField(accessTokenManagerAttributeField);
//		guiDescriptor.addField(externalAppUrlAttributeField);
		guiDescriptor.addField(ldapDatastoreFieldDescriptor);
		guiDescriptor.addField(baseDNAttributeField);
		guiDescriptor.addField(objectClassAttributeField);
		
		// Create the Idp authentication adapter descriptor
		Set<String> contract = new HashSet<String>();
		descriptor = new IdpAuthnAdapterDescriptor(this, "Identity API Adapter", contract, false, guiDescriptor, false);
	}

	public IdpAuthnAdapterDescriptor getAdapterDescriptor() {
		return descriptor;
	}

	@SuppressWarnings("rawtypes")
	public boolean logoutAuthN(Map authnIdentifiers, HttpServletRequest req, HttpServletResponse resp, String resumePath) throws AuthnAdapterException,
			IOException {
		return true;
	}

	public void configure(Configuration configuration) {
		log.debug("Starting configure");
		registerIdentityAPIHandlers(configuration);
	}

	public Map<String, Object> getAdapterInfo() {
		return null;
	}

	@SuppressWarnings("unchecked")
	public AuthnAdapterResponse lookupAuthN(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters) throws AuthnAdapterException,
			IOException {

		log.debug("This should never trigger. Returning failure.");
		AuthnAdapterResponse authnAdapterResponse = new AuthnAdapterResponse();
		authnAdapterResponse.setAuthnStatus(AUTHN_STATUS.FAILURE);
		authnAdapterResponse.setErrorMessage("This should never trigger. Returning failure.");
		return authnAdapterResponse;
	}

	@SuppressWarnings(value = { "rawtypes" })
	public Map lookupAuthN(HttpServletRequest req, HttpServletResponse resp, String partnerSpEntityId, AuthnPolicy authnPolicy, String resumePath)
			throws AuthnAdapterException, IOException {
		throw new UnsupportedOperationException();
	}

	private void logHttpRequest(HttpServletRequest httpRequest) {
		log.info("**** Request " + httpRequest.getMethod() + " for " + httpRequest.getRequestURI());

		log.info("**** Headers");
		Enumeration headerNames = httpRequest.getHeaderNames();
		while (headerNames.hasMoreElements()) {
			String headerName = (String) headerNames.nextElement();
			log.info(headerName + " = " + httpRequest.getHeader(headerName));
		}

		log.info("**** Parameters");
		Enumeration params = httpRequest.getParameterNames();
		while (params.hasMoreElements()) {
			String paramName = (String) params.nextElement();
			log.info(paramName + " = " + httpRequest.getParameter(paramName));
		}
	}

	private void registerIdentityAPIHandlers(Configuration configuration) {
		log.debug("Starting registerHandler");
		HandlerRegistry.registerHandler("/identityapi/registration", new RegistrationServlet(configuration));
		HandlerRegistry.registerHandler("/identityapi/validation", new ValidationServlet(configuration));
		HandlerRegistry.registerHandler("/identityapi/activation", new ActivationServlet(configuration));
		HandlerRegistry.registerHandler("/identityapi/passwordReset", new CompletePasswordResetServlet(configuration));
		HandlerRegistry.registerHandler("/identityapi/passwordResetInit", new InitiatePasswordResetServlet(configuration));
		HandlerRegistry.registerHandler("/identityapi/identityLinking", new LinkIdentityServlet(configuration));
		HandlerRegistry.registerHandler("/identityapi/userStatus", new GetUserStatusServlet(configuration));
	}
	
	
	public static void main(String[] args) throws LDAPException {
		String mail = "myTestemail@gmail.com";
		LDAPConnection c = new LDAPConnection("localhost", 1389, "cn=dmanager", "Password01");
		Collection<Attribute> attributes = new HashSet <Attribute> ();
		attributes.add(new Attribute("objectClass","top"));
		attributes.add(new Attribute("objectClass","veonGlobalIdentity"));
		attributes.add(new Attribute("uid","1234"));
		attributes.add(new Attribute("mail",mail));
		attributes.add(new Attribute("userPassword","Password01"));
		attributes.add(new Attribute("status","registered"));
		c.add("mail="+mail+",ou=People,dc=pingdemo,dc=com", attributes);
	}
	

}