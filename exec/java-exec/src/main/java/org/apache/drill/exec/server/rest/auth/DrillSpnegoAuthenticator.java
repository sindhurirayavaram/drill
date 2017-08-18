/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package org.apache.drill.exec.server.rest.auth;


import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.security.SpnegoLoginService;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.security.authentication.DeferredAuthentication;
import org.eclipse.jetty.security.authentication.SessionAuthentication;
import org.eclipse.jetty.security.authentication.SpnegoAuthenticator;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.UserIdentity;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class DrillSpnegoAuthenticator extends SpnegoAuthenticator {
    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SpnegoAuthService.class);

    public DrillSpnegoAuthenticator() {

    }

    @Override
    public Authentication validateRequest(ServletRequest request, ServletResponse response, boolean mandatory) throws ServerAuthException {

        /*HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse res = (HttpServletResponse)response;
        HttpSession session = req.getSession(true);
        Authentication authentication = (Authentication) session.getAttribute("org.eclipse.jetty.security.UserIdentity");
        if(authentication!=null)
            return authentication;
        else{
            authentication = super.validateRequest(request,response,mandatory);
        }


        Authentication cached = new SessionAuthentication(this.getAuthMethod());
        session.setAttribute("org.eclipse.jetty.security.UserIdentity", cached);


        return authentication;*/
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        HttpSession session = req.getSession(true);
        Authentication authentication = (Authentication) session.getAttribute("org.eclipse.jetty.security.UserIdentity");
        if (authentication != null) {
            return authentication;
        }
        else {
            String header = req.getHeader(HttpHeader.AUTHORIZATION.asString());
            if (!mandatory) {
                return new DeferredAuthentication(this);
            } else if (header == null) {
                try {
                    if (DeferredAuthentication.isDeferred(res)) {
                        return Authentication.UNAUTHENTICATED;
                    } else {
                        // LOG.debug("SpengoAuthenticator: sending challenge", new Object[0]);
                        res.setHeader(HttpHeader.WWW_AUTHENTICATE.asString(), HttpHeader.NEGOTIATE.asString());
                        res.sendError(401);
                        return Authentication.SEND_CONTINUE;
                    }
                } catch (IOException var9) {
                    throw new ServerAuthException(var9);
                }
            } else {
                if (header != null && header.startsWith(HttpHeader.NEGOTIATE.asString())) {
                    String spnegoToken = header.substring(10);
                    UserIdentity user = this.login((String) null, spnegoToken, request);

                    if (user != null) {

                        return new UserAuthentication(this.getAuthMethod(), user);
                    }

                }

                return Authentication.UNAUTHENTICATED;
            }
        }

    }


    public UserIdentity login(String username, Object password, ServletRequest request) {
        UserIdentity user = super.login(username, password, request);
        if (user != null) {
            HttpSession session = ((HttpServletRequest) request).getSession(true);
            Authentication cached = new SessionAuthentication(this.getAuthMethod(), user, password);
            session.setAttribute("org.eclipse.jetty.security.UserIdentity", cached);
        }

        return user;
    }
}
