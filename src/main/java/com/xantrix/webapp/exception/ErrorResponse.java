package com.xantrix.webapp.exception;

import java.util.Date;

import lombok.Data;

@Data
public class ErrorResponse
{
	
	private Date data = new Date();
	private int codice;
	private String messaggio;
	
}
