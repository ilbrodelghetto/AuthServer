package com.xantrix.webapp.service;

import java.net.URI;
import java.net.URISyntaxException;
 
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.xantrix.webapp.exception.NoConnexException;
import com.xantrix.webapp.security.Utenti;
import com.xantrix.webapp.userconf.UserConfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.client.support.BasicAuthorizationInterceptor;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
 
import org.springframework.web.client.RestTemplate;
 
@Service("customUserDetailsService")
public class CustomUserDetailsService implements UserDetailsService
{

	private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

	@Autowired
	private UserConfig Config;

	@Override
	//@Transactional
	public UserDetails loadUserByUsername(String UserId) 
			throws UsernameNotFoundException
	{
		
		 if (UserId == null || UserId.length() < 2) 
		 {
	            throw new UsernameNotFoundException("nome utente assente o non valido"); 
	     } 
		 
		Utenti utente = null;
		
		try 
		{
			utente = this.GetHttpValue(UserId);
		} 
		catch (NoConnexException e) 
		{	 
			 
		}
		 
		 if (utente == null)
		 {
			 throw new UsernameNotFoundException("Utente non Trovato!!");
		 }
		
		 UserBuilder builder = null;
		 
		 builder = org.springframework.security.core.userdetails.User.withUsername(utente.getUserId());
		 builder.disabled((false));
		 builder.password(utente.getPassword());
		 
		 
		 String[] profili = utente.getRuoli()
				 .stream().map(a -> "ROLE_" + a).toArray(String[]::new);
		
		 
		 builder.authorities(profili);
		 

		 return builder.build();
		 
    }
    
	private Utenti GetHttpValue(String UserId) 
		throws NoConnexException 
  	{
		URI url = null;

		try 
		{
			String SrvUrl = Config.getSrvUrl();

			url = new URI(SrvUrl + UserId);
		} 
		catch (URISyntaxException e) 
		{
			 
			e.printStackTrace();
		}

		RestTemplate restTemplate = new RestTemplate();
		restTemplate.getInterceptors().add(new BasicAuthorizationInterceptor(Config.getUserId(), Config.getPassword()));

		Utenti utente = null;

		try 
		{
			utente = restTemplate.getForObject(url, Utenti.class);	
		} 
		catch (Exception e) 
		{
			String ErrMsg = String.format("Connessione al servizio di autenticazione non riuscita!!");
			
			logger.warn(ErrMsg);
			
			throw new NoConnexException(ErrMsg);
		}

		return utente;
    }
	
}
