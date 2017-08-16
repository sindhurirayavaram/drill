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

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.security.UserGroupInformation;
import org.eclipse.jetty.security.SpnegoLoginService;
import org.eclipse.jetty.server.UserIdentity;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;

public class SpnegoAuthService extends SpnegoLoginService {
    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SpnegoAuthService.class);

    private UserIdentity identity;

    private Subject serverSubject;





    public SpnegoAuthService(String name, String config) {

        super(name, config);
   /*    serverSubject = new Subject();
        File keytabFile = new File("/usr/spnego/node163.keytab");
        KeyTab keytabInstance = KeyTab.getInstance(keytabFile);
        serverSubject.getPrivateCredentials().add(keytabFile);
        Principal krbPrincipal = new KerberosPrincipal("HTTP/qa-node163.qa.lab@QA.LAB");
        //String s = System.getProperty("javax.security.auth.useSubjectCredsOnly");
        serverSubject.getPrincipals().add(krbPrincipal);*/




    }

    @Override
    public UserIdentity login(final String username, final Object credentials) {
        try {
            //UserGroupInformation ug = UserGroupInformation.getLoginUser();
           // UserGroupInformation ugi = UserGroupInformation.loginUserFromKeytabAndReturnUGI("HTTP/qa-node163.qa.lab@QA.LAB", "/usr/spnego/node163.keytab");
            final UserGroupInformation ugi;

            if(!UserGroupInformation.isSecurityEnabled()) {


                final Configuration Config = new Configuration();

                Config.set(CommonConfigurationKeys.HADOOP_SECURITY_AUTHENTICATION,
                        UserGroupInformation.AuthenticationMethod.KERBEROS.toString());
                UserGroupInformation.setConfiguration(Config);


            }
            ugi = UserGroupInformation.loginUserFromKeytabAndReturnUGI("HTTP/qa-node163.qa.lab@QA.LAB", "/usr/spnego/node163.keytab");



            identity = ugi.doAs(new PrivilegedExceptionAction<UserIdentity>() {
                @Override
                public UserIdentity run() {
                    return SpnegoAuthService.super.login(username, credentials);
                }
            });
        } catch (Exception e) {
            logger.error("Failed to login using SPNEGO");
        }
        return identity;
    }

}
