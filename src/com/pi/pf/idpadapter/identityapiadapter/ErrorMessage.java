package com.pi.pf.idpadapter.identityapiadapter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;

public class ErrorMessage {
	
	private final Log log = LogFactory.getLog(this.getClass());
	
	public static final String INTERNAL_ERROR = "Internal Error.";
	
	public static final String JSON_PARSING_ERROR = "Error parsing JSON.";

	public static final String LDAP_CONNECTION_ERROR = "LDAP Connection Error.";
	
	public static final String GENERIC_LDAP_ERROR = "Generic LDAP Error.";

	public static final String MISSING_INPUT_DATA = "Missing data. ";

	public static final String USER_REGISTERED_ERROR = "Existing email.";

	public static final String IDENTITY_NOT_FOUND = "Identity Not Found.";
	
	public static final String INVALID_OTP = "Invalid OTP.";

	public static final String CODE_EXPIRED = "Code expired.";

	public static final String USER_ALREADY_EXISTS = "Identity already exists.";

	public static final String NOT_REGISTERED_STATE = "Identity not in registered state.";

	public static final String TOKEN_EXCHANGE_ERROR = "Token exchange error.";
	
	private String result = "error";
	private String errorMessage = "";
	
	public ErrorMessage(String errorMessage) {
		super();
		this.errorMessage = errorMessage;
	}
	
	
	public String getResult() {
		return result;
	}
	public void setResult(String result) {
		this.result = result;
	}
	public String getErrorMessage() {
		return errorMessage;
	}
	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}
	
	public JSONObject toJsonObject () {
		JSONObject object = new JSONObject(this);
		log.debug("Returning " + object.toString());
		return object;
	}
	
	public String toJsonString () {
		JSONObject jsonObject = new JSONObject(this);
		return jsonObject.toString();
	}
	
}
