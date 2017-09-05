/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.server.rest;

import com.google.common.collect.ImmutableSet;
import org.apache.drill.exec.server.rest.auth.DrillRestLoginService;
import org.apache.drill.exec.server.rest.auth.DrillSpnegoAuthenticator;

import org.apache.drill.exec.server.rest.auth.DrillSpnegoLoginService;
import org.apache.drill.exec.work.WorkManager;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.ConstraintAware;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.RoleInfo;
import org.eclipse.jetty.security.SecurityHandler;
import org.eclipse.jetty.security.SpnegoLoginService;
import org.eclipse.jetty.security.authentication.FormAuthenticator;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HandlerContainer;
import org.eclipse.jetty.server.HttpChannel;
import org.eclipse.jetty.server.Request;
import org.apache.drill.exec.work.WorkManager;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.HandlerWrapper;
import org.eclipse.jetty.util.security.Constraint;


import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

import static org.apache.drill.exec.server.rest.auth.DrillUserPrincipal.ADMIN_ROLE;
import static org.apache.drill.exec.server.rest.auth.DrillUserPrincipal.AUTHENTICATED_ROLE;
import static org.apache.drill.exec.server.rest.auth.DrillUserPrincipal.REALM_ROLE;


public class WrapperHandler extends ConstraintSecurityHandler {


    private String auth;

    private final WorkManager workManager;
    CustomConstraintSecurityHandler basicsecurity;
    CustomConstraintSecurityHandler spnegosecurity;

   // private SecurityHandler security;



    public WrapperHandler(WorkManager work) {
        this.workManager = work;
        basicsecurity = new CustomConstraintSecurityHandler();
        Set<String> knownRoles = ImmutableSet.of(AUTHENTICATED_ROLE, ADMIN_ROLE);
        basicsecurity.setConstraintMappings(Collections.<ConstraintMapping>emptyList(), knownRoles);

        basicsecurity.setAuthenticator(new FormAuthenticator("/login", "/login", true));
        basicsecurity.setLoginService(new DrillRestLoginService(workManager.getContext()));
        //basicsecurity.setHandler(getCurrentSecurityHandler());*/
       spnegosecurity = new CustomConstraintSecurityHandler();
       Constraint constraint = new Constraint();
        constraint.setName(Constraint.__SPNEGO_AUTH);
        constraint.setRoles(new String[]{ADMIN_ROLE,AUTHENTICATED_ROLE});
        constraint.setAuthenticate(true);

        ConstraintMapping cm = new ConstraintMapping();
        cm.setConstraint(constraint);
        cm.setPathSpec("/*");

        Constraint rootConstraint = new Constraint();
        rootConstraint.setAuthenticate(false);
        ConstraintMapping cm1 = new ConstraintMapping();
        cm1.setConstraint(rootConstraint);
        cm1.setPathSpec("/");

        spnegosecurity.setAuthenticator(new DrillSpnegoAuthenticator());
       final SpnegoLoginService loginService = new DrillSpnegoLoginService("QA.LAB","/etc/spnego.properties",workManager.getContext());
        final IdentityService identityService = new DefaultIdentityService();
        loginService.setIdentityService(identityService);
        spnegosecurity.setLoginService(loginService);

        List<ConstraintMapping> cmapList = new ArrayList<>();
      //  cmapList.add(cm1);
        cmapList.add(cm);
        spnegosecurity.setConstraintMappings(cmapList,knownRoles);
       // spnegosecurity.setHandler(getCurrentSecurityHandler());

    }

    @Override
    public void doStart() throws Exception {
        spnegosecurity.doStart();
        basicsecurity.doStart();
        super.doStart();
    }


   @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {

       //spnegosecurity.handle(target, baseRequest, request, response);

        HttpServletRequest req = (HttpServletRequest)baseRequest;
        String header = req.getHeader(HttpHeader.AUTHORIZATION.asString());
       HttpSession session = req.getSession(true);
       Authentication authentication = (Authentication) session.getAttribute("org.eclipse.jetty.security.UserIdentity");
       String uri = req.getRequestURI();
       auth = "spnego";
    /*   if(header != null && header.startsWith("NEGOTIATE")){
           auth = "spnego";
       } */

/* if(header == null && authentication == null && uri.equals("/login")) {
          response.setHeader(HttpHeader.WWW_AUTHENTICATE.asString(), HttpHeader.NEGOTIATE.asString());
        response.sendError(401);
        baseRequest.setHandled(true);
            Handler handler = this.getHandler();
            handler.handle(target, baseRequest, request, response);
        }*/

        //if(authentication != null)
         if( auth.equals("spnego") ){
            spnegosecurity.handle(target, baseRequest, request, response);
        }
        //}
       else  {
            basicsecurity.handle(target, baseRequest, request, response);
          //  spnegosecurity.handle(target, baseRequest, request, response);

            }

    }

    @Override
    public void setHandler(Handler handler) {
        super.setHandler(handler);
        spnegosecurity.setHandler(handler);
        basicsecurity.setHandler(handler);


    }

   /* @Override
    public void setRoles(Set<String> roles) {
        Set<String> updatedRoleSets = basicsecurity.getRoles();
        updatedRoleSets.addAll(roles);
        basicsecurity.setRoles(updatedRoleSets);
        Set<String> updatedRoleSet = spnegosecurity.getRoles();
        updatedRoleSet.addAll(roles);
        spnegosecurity.setRoles(updatedRoleSet);


    }

   /* @Override
    protected RoleInfo prepareConstraintInfo(String s, Request request) {
        return null;
    }

    @Override
    protected boolean checkUserDataPermissions(String s, Request request, Response response, RoleInfo roleInfo) throws IOException {
        return false;
    }

    @Override
    protected boolean isAuthMandatory(Request request, Response response, Object o) {
        return false;
    }

    @Override
    protected boolean checkWebResourcePermissions(String s, Request request, Response response, Object o, UserIdentity userIdentity) throws IOException {
        return false;
    }*/


   /* private void createSecurityHandler() {

        //ConstraintSecurityHandler security = new ConstraintSecurityHandler();
        Set<String> knownRoles = ImmutableSet.of(AUTHENTICATED_ROLE, ADMIN_ROLE);
        this.setConstraintMappings(Collections.<ConstraintMapping>emptyList(), knownRoles);

        this.setAuthenticator(new FormAuthenticator("/login", "/login", true));
        this.setLoginService(new DrillRestLoginService(workManager.getContext()));


    }*/


    //public SecurityHandler getSecurity(){
    //     return security;
    //}

}
