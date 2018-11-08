package com.xantrix.webapp.security;

import java.io.IOException;
import java.sql.Date;
import java.util.Collections;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter
{
	private static final Logger logger = LoggerFactory.getLogger(JwtUsernameAndPasswordAuthenticationFilter.class);
	
	// We use auth manager to validate the user credentials
	private AuthenticationManager authManager;

	private final JwtConfig jwtConfig;
	
	public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authManager, JwtConfig jwtConfig)
	{
		this.authManager = authManager;
		this.jwtConfig = jwtConfig;

		// By default, UsernamePasswordAuthenticationFilter listens to "/login"
		// path.
		// In our case, we use "/auth". So, we need to override the defaults.
		this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(jwtConfig.getUri(), "POST"));
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException
	{

		try
		{

			// 1. Otteniamo le credenziali dal request
			UserCredentials creds = new ObjectMapper().readValue(request.getInputStream(), UserCredentials.class);
			
			logger.info("UserId: " + creds.getUsername() + "  Password: " + creds.getPassword());

			// 2. Creiamo l'oggetto auth (contains credentials) che sarà usoto dal
			// auth manager
			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(creds.getUsername(),
					creds.getPassword(), Collections.emptyList());
			
			// 3. Authentication manager autentica l'utente,ed usa
			// il loadUserByUsername() per ottenere i dati
			// dell'utente
			return authManager.authenticate(authToken);

		} 
		catch (IOException e)
		{
			throw new RuntimeException(e);
		}
	}

	// Upon successful authentication, generate a token.
	// The 'auth' passed to successfulAuthentication() is the current
	// authenticated user.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication auth) throws IOException, ServletException
	{

		Long now = System.currentTimeMillis();
		String token = Jwts.builder().setSubject(auth.getName())
				// Convert to list of strings.
				// This is important because it affects the way we get them back
				// in the Gateway.
				.claim("authorities", auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
				.setIssuedAt(new Date(now)).setExpiration(new Date(now + jwtConfig.getExpiration() * 1000)) // in  milliseconds																										 
				.signWith(SignatureAlgorithm.HS512, jwtConfig.getSecret().getBytes()).compact();

		String FullToken = "Token: " + jwtConfig.getPrefix() + " " + token;
		
		logger.warn(FullToken);

		// Add token to header
		response.addHeader(jwtConfig.getHeader(), FullToken);
	}

	
}
