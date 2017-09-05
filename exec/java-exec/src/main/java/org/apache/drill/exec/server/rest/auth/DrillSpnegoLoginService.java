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

import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.server.DrillbitContext;
import org.apache.drill.exec.server.options.SystemOptionManager;
import org.apache.drill.exec.util.ImpersonationUtil;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.SpnegoLoginService;
import org.eclipse.jetty.security.SpnegoUserPrincipal;
import org.eclipse.jetty.security.authentication.SessionAuthentication;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.B64Code;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.util.regex.Pattern;

public class DrillSpnegoLoginService extends SpnegoLoginService implements LoginService {
    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DrillSpnegoLoginService.class);

    private UserIdentity identity;

    private Subject serverSubject;

    private Subject sub;

    private final String serverPrincipal;

    private final DrillbitContext drillContext;


    public DrillSpnegoLoginService(String name, String config, final DrillbitContext drillbitContext) {

        super(name, config);
        serverSubject = new Subject();
        File keytabFile = new File("/usr/spnego/node163.keytab");
        KeyTab keytabInstance = KeyTab.getInstance(keytabFile);
        serverSubject.getPrivateCredentials().add(keytabFile);
        String[] spnegoPrincipals = new String[]{};
      /*  try {
            spnegoPrincipals = KerberosUtil.getPrincipalNames(
                    "/usr/spnego/node163.keytab", Pattern.compile("HTTP/.*"));
        } catch (Exception ex) {
            logger.debug("No principals found");
        }*/

        //  for (String principal : spnegoPrincipals) {
        //    final KerberosPrincipal krbPrincipal = new KerberosPrincipal(principal);
        //  serverSubject.getPrincipals().add(krbPrincipal);
        //}

        KerberosPrincipal krbPrincipal = new KerberosPrincipal("HTTP/qa-node163.qa.lab@QA.LAB");
        serverSubject.getPrincipals().add(krbPrincipal);
        // System.setProperty("javax.security.auth.useSubjectCredsOnly","false");
        serverPrincipal = name;
        drillContext = drillbitContext;

    }


    @Override
    public UserIdentity login(final String username, final Object credentials) {
        try {
            //UserGroupInformation ug = UserGroupInformation.getLoginUser();
            // UserGroupInformation ugi = UserGroupInformation.loginUserFromKeytabAndReturnUGI("HTTP/qa-node163.qa.lab@QA.LAB", "/usr/spnego/node163.keytab");
            final UserGroupInformation ugi;

            if (!UserGroupInformation.isSecurityEnabled()) {


                final Configuration Config = new Configuration();

                Config.set(CommonConfigurationKeys.HADOOP_SECURITY_AUTHENTICATION,
                        UserGroupInformation.AuthenticationMethod.KERBEROS.toString());
                UserGroupInformation.setConfiguration(Config);


            }
            ugi = UserGroupInformation.loginUserFromKeytabAndReturnUGI("HTTP/qa-node163.qa.lab@QA.LAB", "/usr/spnego/node163.keytab");


            /*LoginContext loginContext = new LoginContext("hadoop-user-kerberos", serverSubject);
            loginContext.login();
            sub = loginContext.getSubject();*/


         /*   identity = Subject.doAs(serverSubject, new PrivilegedExceptionAction<UserIdentity>() {
                @Override
                public UserIdentity run() throws Exception {
                    return spnegologin(username, credentials);
                }
            });*/
            identity = ugi.doAs(new PrivilegedExceptionAction<UserIdentity>() {
                @Override
                public UserIdentity run() throws Exception {
                    identity = spnegologin(username, credentials);
                    return identity;
                }
            });

            Subject userSubject = identity.getSubject();


        } catch (Exception e) {
            logger.error("Failed to login using SPNEGO");
        }
        return identity;
    }

    public UserIdentity spnegologin(String username, Object credentials) {
        String encodedAuthToken = (String) credentials;
        byte[] authToken = B64Code.decode(encodedAuthToken);
        GSSManager manager = GSSManager.getInstance();

        try {
            Oid krb5Oid = new Oid("1.3.6.1.5.5.2");
            //    Oid krb5Oid1 = new Oid("1.2.840.113554.1.2.2");
            //    Oid krb5Oid2 = new Oid("1.2.840.113554.1.2.2.1");
            GSSName gssName = manager.createName("HTTP/qa-node163.qa.lab", (Oid) null);
            GSSCredential serverCreds = manager.createCredential(gssName, 2147483647, krb5Oid, 2);
            GSSContext gContext = manager.createContext(serverCreds);
            if (gContext == null) {
                //LOG.debug("SpnegoUserRealm: failed to establish GSSContext", new Object[0]);
            } else {
                while (!gContext.isEstablished()) {
                    authToken = gContext.acceptSecContext(authToken, 0, authToken.length);
                }

                if (gContext.isEstablished()) {
                    String clientName = gContext.getSrcName().toString();
                    String role = clientName.substring(0, clientName.indexOf(64));
                    // LOG.debug("SpnegoUserRealm: established a security context", new Object[0]);
                    //LOG.debug("Client Principal is: " + gContext.getSrcName(), new Object[0]);
                    // LOG.debug("Server Principal is: " + gContext.getTargName(), new Object[0]);
                    // LOG.debug("Client Default Role: " + role, new Object[0]);
                    final SystemOptionManager sysOptions = drillContext.getOptionManager();

                    final boolean isAdmin = ImpersonationUtil.hasAdminPrivileges(role,
                            sysOptions.getOption(ExecConstants.ADMIN_USERS_KEY).string_val,
                            sysOptions.getOption(ExecConstants.ADMIN_USER_GROUPS_KEY).string_val);
                    SpnegoUserPrincipal user = new SpnegoUserPrincipal(clientName, authToken);
                    Subject subject = new Subject();
                    subject.getPrincipals().add(user);
                    if (isAdmin) {
                        return this._identityService.newUserIdentity(subject, user, DrillUserPrincipal.ADMIN_USER_ROLES);
                    } else {
                        return this._identityService.newUserIdentity(subject, user, DrillUserPrincipal.NON_ADMIN_USER_ROLES);
                    }
                }
            }
        } catch (GSSException var14) {
            //LOG.warn(var14);
        }

        return null;
    }

    @Override
    public void logout(UserIdentity user) {
        // no-op
        if (logger.isTraceEnabled()) {
            logger.trace("Web user {} logged out.", user.getUserPrincipal().getName());
        }
    }

}


