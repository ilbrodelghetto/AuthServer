package com.xantrix.webapp.exception;

public class NoConnexException extends Exception
{
	private static final long serialVersionUID = 1L;
	
	private String messaggio;
	
	public NoConnexException()
	{
		super();
	}
	
	public NoConnexException(String Messaggio)
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
