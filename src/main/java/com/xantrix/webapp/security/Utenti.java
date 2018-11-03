package com.xantrix.webapp.security;

import java.util.List;

import lombok.Data;

@Data
public class Utenti
{
	private String id;
	
	private String userId;
	private String password;
	
	private List<String> ruoli;	
}
