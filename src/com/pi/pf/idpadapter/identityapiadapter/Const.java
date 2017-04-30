package com.pi.pf.idpadapter.identityapiadapter;

public class Const {
	public static final String ATTR_OAUTH_CLIENT_NAME = "OAuth client";
	public static final String ATTR_OAUTH_CLIENT_LABEL = "OAuth client in the JWT token sent to the external app";

	public static final String ATTR_OAUTH_SCOPES_NAME = "OAuth scopes";
	public static final String ATTR_OAUTH_SCOPES_LABEL = "OAuth scopes in the JWT token sent to the external app (list of scopes separated with space)";

	public static final String ATTR_ACCESS_TOKEN_MANAGER_NAME = "Access token manager";
	public static final String ATTR_ACCESS_TOKEN_MANAGER_LABEL = "Access token manager used to issue the JWT token sent to the external app";

	public static final String ATTR_EXTERNAL_APP_URL_NAME = "External app url";
	public static final String ATTR_EXTERNAL_APP_URL_LABEL = "External app url; the adapter posts the JWT token to this url";
	
	public static final String LDAP_DATASOURCE_NAME = "LDAP Data source";
	public static final String LDAP_DATASOURCE_LABEL = "The LDAP data source used for registering identities";
	
	public static final String BASE_DN_NAME = "LDAP base DN";
	public static final String BASE_DN_LABEL = "LDAP base DN";
	
	public static final String OBJECT_CLASS_NAME = "Object class";
	public static final String OBJECT_CLASS_LABEL = "LDAP object class of the entry created";
	
	public static final String EMAIL_ATTRIBUTE_NAME = "mail";
	
	public static final String REGISTERED = "registered";
	public static final String ACTIVE = "active";
	public static final String STATUS = "status";
	public static final String CODE = "code";
	public static final String GLOBAL_UID = "globalUID";
	public static final String USER_PASSWORD = "userPassword";
	
	public static final int TOKEN_DURATION_MINUTES = 10;
	
	public static final String MESSAGE_TEMPLATE_REGISTRATION_HTML = "message-template-register.html";
	
	
	
}
