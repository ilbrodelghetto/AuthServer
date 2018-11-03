package com.xantrix.webapp.exception;

public class BindingException extends Exception
{
	private static final long serialVersionUID = 1L;
	
	private String messaggio;
	
	public BindingException()
	{
		super();
	}
	
	public BindingException(String Messaggio)
	{
		super(Messaggio);
		this.messaggio = Messaggio;
	}

	public String getMessaggio()
	{
		return messaggio;
	}

	public void setMessaggio(String messaggio)
	{
		this.messaggio = messaggio;
	}

}
