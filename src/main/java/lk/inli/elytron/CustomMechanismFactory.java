/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package lk.inli.elytron;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 *
 * @author indika
 */
public class CustomMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    static final String CUSTOM_NAME = "CUSTOM_MECHANISM";

    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String name, Map<String, ?> properties, CallbackHandler handler) throws HttpAuthenticationException {
        if (CUSTOM_NAME.equals(name)) {
            /*
             * The properties could be used at this point to further customise the behaviour of the mechanism.
             */
            return new CustomHeaderHttpAuthenticationMechanism(handler);
        }

        return null;
    }

    public String[] getMechanismNames(Map<String, ?> properties) {
        /*
         * At this stage the properties could be queried to only return a mechanism if compatible with the properties provided.
         */
        return new String[]{CUSTOM_NAME};
    }
}
