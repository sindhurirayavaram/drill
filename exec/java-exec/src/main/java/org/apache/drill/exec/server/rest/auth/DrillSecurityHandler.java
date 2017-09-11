/*
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


package org.apache.drill.exec.server.rest.auth;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.common.exceptions.DrillException;
import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.exception.DrillbitStartupException;
import org.apache.drill.exec.work.WorkManager;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.SpnegoLoginService;
import org.eclipse.jetty.security.authentication.FormAuthenticator;
import org.eclipse.jetty.security.authentication.SessionAuthentication;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.apache.drill.exec.server.rest.auth.DrillUserPrincipal.ADMIN_ROLE;
import static org.apache.drill.exec.server.rest.auth.DrillUserPrincipal.AUTHENTICATED_ROLE;


public class DrillSecurityHandler extends ConstraintSecurityHandler {

    private DrillConfig DrillConfig;
    private final WorkManager workManager;
    private DrillConstraintSecurityHandler basicSecurityHandler;
    private DrillConstraintSecurityHandler spnegoSecurityHandler;
    private final String HTTP_FORM ="FORM";
    private final String HTTP_SPNEGO ="SPNEGO";
    private List<String> configuredMechanisms = Lists.newArrayList();
    private Set<String> knownRoles = ImmutableSet.of(AUTHENTICATED_ROLE, ADMIN_ROLE);
    private SpnegoUtil spnUtil;

    public DrillSecurityHandler(DrillConfig config,WorkManager work) throws DrillbitStartupException,IOException {
        DrillConfig = config;
        spnUtil = new SpnegoUtil(config);
        this.workManager = work;
        try {
            if (config.hasPath(ExecConstants.HTTP_AUTHENTICATION_MECHANISMS)) {
                configuredMechanisms = config.getStringList(ExecConstants.HTTP_AUTHENTICATION_MECHANISMS);
                if (configuredMechanisms.contains(HTTP_FORM)) {
                    initializeFormAuthentication();

                }
                if (configuredMechanisms.contains(HTTP_SPNEGO)) {
                    initializeSpnegoAuthentication();

                }
            }
        }
        catch(DrillException e){
            throw new DrillbitStartupException(e.getMessage(), e);
        }
        //Backward compatability for Form authentication
        if(!config.hasPath(ExecConstants.HTTP_AUTHENTICATION_MECHANISMS)){
            initializeFormAuthentication();
        }
    }

    public void initializeFormAuthentication(){
        basicSecurityHandler = new DrillConstraintSecurityHandler();
        basicSecurityHandler.setConstraintMappings(Collections.<ConstraintMapping>emptyList(), knownRoles);
        basicSecurityHandler.setAuthenticator(new FormAuthenticator("/login", "/login", true));
        basicSecurityHandler.setLoginService(new DrillRestLoginService(workManager.getContext()));


    }

    public void initializeSpnegoAuthentication() throws DrillException {
        spnegoSecurityHandler = new DrillConstraintSecurityHandler();
        spnegoSecurityHandler.setAuthenticator(new DrillSpnegoAuthenticator());
        final SpnegoLoginService loginService = new DrillSpnegoLoginService(spnUtil.getSpnegoRealm(),spnUtil.getSpnegoPrincipal(),workManager.getContext(),spnUtil.getUgi());
        final IdentityService identityService = new DefaultIdentityService();
        loginService.setIdentityService(identityService);
        spnegoSecurityHandler.setLoginService(loginService);
        spnegoSecurityHandler.setConstraintMappings(Collections.<ConstraintMapping>emptyList(),knownRoles);

    }

    @Override
    public void doStart() throws Exception {
        super.doStart();
        if(!configuredMechanisms.isEmpty() && configuredMechanisms.contains(HTTP_SPNEGO)) {
            spnegoSecurityHandler.doStart();
        }
        if(configuredMechanisms.isEmpty() || configuredMechanisms.contains(HTTP_FORM) ) {
            basicSecurityHandler.doStart();
        }

    }


    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest)baseRequest;
        String header = req.getHeader(HttpHeader.AUTHORIZATION.asString());
        HttpSession session = req.getSession(true);
        SessionAuthentication authentication = (SessionAuthentication) session.getAttribute("org.eclipse.jetty.security.UserIdentity");
        String uri = req.getRequestURI();
        //Before authentication, all requests go through the Formauthenticator except for Spnegologin request
        //If this authentication is null, user hasn't logged in yet
        if(authentication == null){
            if( uri.equals("/sn") ){
                spnegoSecurityHandler.handle(target, baseRequest, request, response);
            }
            else {
                basicSecurityHandler.handle(target, baseRequest, request, response);
            }

        }
        //If user has logged in, use the corresponding handler to handle the request
        else{
            if(authentication.getAuthMethod() == "FORM"){
                basicSecurityHandler.handle(target, baseRequest, request, response);
            }
            else if(authentication.getAuthMethod() == "SPNEGO"){
                spnegoSecurityHandler.handle(target, baseRequest, request, response);
            }
        }
    }

    @Override
    public void setHandler(Handler handler) {
        super.setHandler(handler);
        if(!configuredMechanisms.isEmpty() && configuredMechanisms.contains(HTTP_SPNEGO)) {
            spnegoSecurityHandler.setHandler(handler);
        }
        if(configuredMechanisms.isEmpty() || configuredMechanisms.contains(HTTP_SPNEGO)) {
            basicSecurityHandler.setHandler(handler);
        }
    }
    }