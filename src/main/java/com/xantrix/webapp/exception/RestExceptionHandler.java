package com.xantrix.webapp.exception;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
@RestController
public class RestExceptionHandler extends  
	ResponseEntityExceptionHandler
{
	@ExceptionHandler(NotFoundException.class)
	public final ResponseEntity<ErrorResponse> exceptionNotFoundHandler(Exception ex)
	{
		ErrorResponse errore = new ErrorResponse();
		
		errore.setCodice(HttpStatus.NOT_FOUND.value());
		errore.setMessaggio(ex.getMessage());
		
		return new ResponseEntity<ErrorResponse>(errore, new HttpHeaders(), HttpStatus.NOT_FOUND);
	}
	
	@ExceptionHandler(BindingException.class)
	public ResponseEntity<ErrorResponse> exceptionBindingHandler(Exception ex)
	{
		ErrorResponse errore = new ErrorResponse();
		
		errore.setCodice(HttpStatus.BAD_REQUEST.value());
		errore.setMessaggio(ex.getMessage());
		
		return new ResponseEntity<ErrorResponse>(errore, new HttpHeaders(), HttpStatus.BAD_REQUEST);
	}
	
	@ExceptionHandler(DuplicateException.class)
	public ResponseEntity<ErrorResponse> exceptionDeplicateRecordHandler(Exception ex)
	{
		ErrorResponse errore = new ErrorResponse();
		
		errore.setCodice(HttpStatus.NOT_ACCEPTABLE.value());
		errore.setMessaggio(ex.getMessage());
		
		return new ResponseEntity<ErrorResponse>(errore, HttpStatus.NOT_ACCEPTABLE);
    }
    
	@ExceptionHandler(Exception.class)
	public ResponseEntity<ErrorResponse> exceptionHandler(Exception ex)
	{
		ErrorResponse errore = new ErrorResponse();
		
		errore.setMessaggio("La richiesta non può essere eseguita a causa di un errore generico");
		errore.setCodice(HttpStatus.BAD_REQUEST.value());
		
		return new ResponseEntity<ErrorResponse>(errore, HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(NoConnexException.class)
	public ResponseEntity<ErrorResponse> exceptionConnectionHandler(Exception ex)
	{
		ErrorResponse errore = new ErrorResponse();
		
		errore.setCodice(HttpStatus.SERVICE_UNAVAILABLE.value());
		errore.setMessaggio(ex.getMessage());
		
		return new ResponseEntity<ErrorResponse>(errore, new HttpHeaders(), HttpStatus.BAD_REQUEST);
	}
	
}
