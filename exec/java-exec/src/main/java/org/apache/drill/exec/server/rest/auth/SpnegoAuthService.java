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

import org.apache.hadoop.security.UserGroupInformation;
import org.eclipse.jetty.security.SpnegoLoginService;
import org.eclipse.jetty.server.UserIdentity;

import javax.servlet.http.HttpServletRequest;
import java.security.PrivilegedAction;

public class SpnegoAuthService extends SpnegoLoginService {
    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SpnegoAuthService.class);

    private UserIdentity identity;


    public SpnegoAuthService(String name, String config) {
        super(name, config);
    }

    @Override
    public UserIdentity login(final String username, final Object credentials) {
        try {
            UserGroupInformation ugi = UserGroupInformation.getLoginUser();

            identity = ugi.doAs(new PrivilegedAction<UserIdentity>() {
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
