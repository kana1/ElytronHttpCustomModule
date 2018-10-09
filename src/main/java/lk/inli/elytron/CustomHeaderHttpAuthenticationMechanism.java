/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package lk.inli.elytron;

import static lk.inli.elytron.CustomMechanismFactory.CUSTOM_NAME;

import java.io.IOException;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import org.jboss.logging.Logger;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.CachedIdentityAuthorizeCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.http.Scope;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 *
 * @author indika
 */
public class CustomHeaderHttpAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    /*
     * As the mechanism is instantiated by a factory it is generally a good practice to minimise visibility.
     */
    private static final String USERNAME_HEADER = "X-USERNAME";
    private static final String PASSWORD_HEADER = "X-PASSWORD";
    private static final String MESSAGE_HEADER = "X-MESSAGE";
    private Logger log = Logger.getLogger(this.getClass());

    private final String contextPath = "";
    private static final String CACHED_IDENTITY_KEY = CustomHeaderHttpAuthenticationMechanism.class.getName() + ".elytron-identity";
    
    
    private static final HttpServerMechanismsResponder RESPONDER = new HttpServerMechanismsResponder() {
        /*
         * As the responses are always the same a static instance of the responder can be used.
         */

        public void sendResponse(HttpServerResponse response) throws HttpAuthenticationException {
            response.addResponseHeader(
            		MESSAGE_HEADER, 
            		"Please resubit the request with a username specified using the X-USERNAME and a password specified using the X-PASSWORD header.");
            response.setStatusCode(401);
        }
    };
    
    private static final HttpServerMechanismsResponder LOGIN_FORM_RESPONDER = new HttpServerMechanismsResponder() {
        /*
         * As the responses are always the same a static instance of the responder can be used.
         */

        public void sendResponse(HttpServerResponse response) throws HttpAuthenticationException {
            response.forward("/login_form.jsp");
            //response.setStatusCode(401);
        }
    };

    private final CallbackHandler callbackHandler;

    /**
     * @param callbackHandler
     */
    CustomHeaderHttpAuthenticationMechanism(final CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        
    	log.infof("Request method %s , path %s", request.getRequestMethod(), request.getRequestURI().getPath());

    	// try to re-authenticate based on a previously cached identity
        if (attemptReAuthentication(request)) {
        	log.info("Re-authentication succeed");
            return;
            //https://github.com/wildfly-security/wildfly-elytron/blob/master/src/main/java/org/wildfly/security/http/impl/FormAuthenticationMechanism.java
            //https://github.com/wildfly-security/wildfly-elytron/blob/38e1e01972414ad70710a4922e259de4eec9ddfd/src/main/java/org/wildfly/security/http/impl/FormAuthenticationMechanism.java
        }
    	
        // not a authenticated request !!
        attemptAuthentication(request);
        
    	
    }

    
    
    
    private void attemptAuthentication(HttpServerRequest request) throws HttpAuthenticationException {

    	String username = null;
        String password = null;

        
        List<String> uids = request.getParameterValues("j_username");
        List<String> pwds = request.getParameterValues("j_password");

        if (uids == null || uids.size()== 0 || pwds == null || pwds.size()== 0) {
            /*
             * This mechanism is not performing authentication at this time however other mechanisms may be in use concurrently and could succeed so we register
             */
            log.debug("evaluateRequest(): either username or password empty ...");
            request.noAuthenticationInProgress(LOGIN_FORM_RESPONDER);
            return;
        }
        if (uids != null && uids.size() > 0) {
            username = uids.get(0);
        }
        if (pwds != null && pwds.size() > 0) {
            password = pwds.get(0);
        }

        /*
         * The first two callbacks are used to authenticate a user using the supplied username and password.
         */
        NameCallback nameCallback = new NameCallback("Remote Authentication Name", username);
        nameCallback.setName(username);
        
        final PasswordGuessEvidence evidence = new PasswordGuessEvidence(password.toCharArray());
        EvidenceVerifyCallback evidenceVerifyCallback = new EvidenceVerifyCallback(evidence);

        try {
            callbackHandler.handle(
            		new Callback[]{nameCallback, evidenceVerifyCallback});
        
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        }

        if (evidenceVerifyCallback.isVerified() == false) {
            request.authenticationFailed("Username / Password Validation Failed", RESPONDER);
        }

        /*
         * This next callback is optional, as we have the users password we can associate it with the private credentials of the
         * SecurityIdentity so it can be used again later.
         */
        try {
        
        	callbackHandler.handle(new Callback[]{new IdentityCredentialCallback(
            		new PasswordCredential(
            				ClearPassword.createRaw(
            						ClearPassword.ALGORITHM_CLEAR, 
            						password.toCharArray())), true)});
        
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        }

        
        //authenticated user should come here
        IdentityCache identityCache = createIdentityCache(request); 
        
        
        /*
         * The next callback is important, although at this stage they are authenticated an authorization check is now needed to
         * ensure the user has the LoginPermission granted allowing them to login.
         */
//        AuthorizeCallback authorizeCallback = new AuthorizeCallback(username, username);

        try {
//            callbackHandler.handle(new Callback[]{authorizeCallback});

            /*
             * Finally this example is very simple so we can deduce the outcome from the callbacks so far, however some
             * mechanisms may still go on to take additional information into account and make an alternative decision so a
             * callback is required to report the final outcome.
             */
            
        	if (cachedItendityAuthorize(username, request, identityCache)) {// !!

        		log.infof("User [%s] authenticated successfully", username);

        		//HttpScope session = getSessionScope(request, true);
        		
                callbackHandler.handle(
                		new Callback[]{AuthenticationCompleteCallback.SUCCEEDED});
                request.authenticationComplete();

            } else {
                callbackHandler.handle(
                		new Callback[]{AuthenticationCompleteCallback.FAILED});
                request.authenticationFailed("Authorization check failed.", RESPONDER);
            }
            return;
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        }
		
	}


    
    protected boolean authorize(String username) throws HttpAuthenticationException {
        log.debugf("Username authorization. Username: [%s].",
                username);

        /*
         * The next callback is important, although at this stage they are authenticated an authorization check is now needed to
         * ensure the user has the LoginPermission granted allowing them to login.
         */
        
        AuthorizeCallback authorizeCallback = new AuthorizeCallback(username, username);

        try {
            callbackHandler.handle(new Callback[] {authorizeCallback});

            
            /*
             * Finally this example is very simple so we can deduce the outcome from the callbacks so far, however some
             * mechanisms may still go on to take additional information into account and make an alternative decision so a
             * callback is required to report the final outcome.
             */
                        
            return authorizeCallback.isAuthorized();
        
        } catch (UnsupportedCallbackException e) {
            return false;
        } catch (IOException e) {
            throw new HttpAuthenticationException(e);
        }
    }
    
    private boolean cachedItendityAuthorize(String username, HttpServerRequest request, IdentityCache identityCache) throws HttpAuthenticationException {
        log.infof("Authorizing username: [%s], Request URI: [%s], Context path: [%s]", username, request.getRequestURI(), this.contextPath);

        if (identityCache != null) {
            CachedIdentityAuthorizeCallback authorizeCallback = new CachedIdentityAuthorizeCallback(username, identityCache);
            try {
                callbackHandler.handle(new Callback[]{authorizeCallback});
                return authorizeCallback.isAuthorized();
            } catch (IOException | UnsupportedCallbackException e) {
                throw new HttpAuthenticationException(e);
            }
        }
        return this.authorize(username);
}
    

	private boolean attemptReAuthentication(HttpServerRequest request) throws HttpAuthenticationException {
    	
    	HttpScope sessionScope = getSessionScope(request, false);
    	
    	if (sessionScope != null && sessionScope.exists()) {
    		log.infof("Trying to re-authenticate session %s. Request URI: [%s], Context path: [%s]",
    				sessionScope.getID(), request.getRequestURI(), this.contextPath);
    	}else {
    		log.warnf("Trying to re-authenticate. There is no session attached to the following request. " +
    				"Request URI: [%s], Context path: [%s]", request.getRequestURI(), this.contextPath);
    	}
    	
    	IdentityCache identityCache = createIdentityCache(request);
    	
    	if (identityCache != null) {
    		

            CachedIdentityAuthorizeCallback authorizeCallback = new CachedIdentityAuthorizeCallback(identityCache);
            try {
                callbackHandler.handle(new Callback[]{authorizeCallback});
            } catch (IOException | UnsupportedCallbackException e) {
                throw new HttpAuthenticationException(e);
            }
            
            if (authorizeCallback.isAuthorized()) { // authnticated but not autharized get passed here ??? 

            	try {
            		callbackHandler.handle(
                    		new Callback[]{AuthenticationCompleteCallback.SUCCEEDED});
            		
                } catch (IOException | UnsupportedCallbackException e) {
                    throw new HttpAuthenticationException(e);
                }
            	
            	request.authenticationComplete();
            	//request.resumeRequest(); // do we need this??
            	return true;

            }else {
            	
				log.error("Is not authorized.........");
			}
            
            
    	}    	
		return false;
	}



    private IdentityCache createIdentityCache(HttpServerRequest request) {

    		 return new IdentityCache() {

				@Override
				public CachedIdentity get() {
					HttpScope session = getSessionScope(request, false);

	                if (session == null || !session.exists()) {
	                    return null;
	                }

	                return (CachedIdentity) session.getAttachment(CACHED_IDENTITY_KEY);
				}

				@Override
				public void put(SecurityIdentity identity) {
					HttpScope session = getSessionScope(request, true);

	                if (session == null || !session.exists()) {
	                    return;
	                }
	                session.setAttachment(CACHED_IDENTITY_KEY, new CachedIdentity(getMechanismName(), identity));
					
				}

				@Override
				public CachedIdentity remove() {
					// logout equivalent ?
					HttpScope session = getSessionScope(request, false);

	                if (session == null || !session.exists()) {
	                    return null;
	                }

	                CachedIdentity cachedIdentity = get();

	                session.setAttachment(CACHED_IDENTITY_KEY, null);

	                return cachedIdentity;
				}
    			 
    		 };

    }



	private HttpScope getSessionScope(HttpServerRequest request, boolean createSession) {
        HttpScope scope = request.getScope(Scope.SESSION);

        if (scope != null &&!scope.exists() && createSession) {
            scope.create();
        }

        return scope;
}



	public String getMechanismName() {
        return CUSTOM_NAME;
    }
}
