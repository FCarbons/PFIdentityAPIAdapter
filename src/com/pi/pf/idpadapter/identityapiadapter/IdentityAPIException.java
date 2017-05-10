package com.pi.pf.idpadapter.identityapiadapter;

public class IdentityAPIException extends Exception {

	private static final long serialVersionUID = 1L;

	ErrorMessage error;
	
	
	
	public IdentityAPIException(ErrorMessage error) {
		super();
		this.error = error;
	}



	public ErrorMessage getError() {
		return error;
	}



	public void setError(ErrorMessage error) {
		this.error = error;
	}
	
	
	
	
	
	
}
