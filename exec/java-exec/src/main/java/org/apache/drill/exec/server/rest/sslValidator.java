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
package org.apache.drill.exec.server.rest;

import com.typesafe.config.Config;
import org.apache.drill.common.exceptions.DrillException;
import org.apache.drill.exec.ExecConstants;



public  class sslValidator {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(sslValidator.class);

  private final String keystorePath;

  private final String keystorePassword;

  private final String truststorePassword;

  private final String truststorePath;

  public boolean validateKeystore = false;

  public sslValidator(Config config) throws DrillException {

    keystorePath = config.getString(ExecConstants.HTTP_KEYSTORE_PATH);

    keystorePassword = config.getString(ExecConstants.HTTP_KEYSTORE_PASSWORD);

    truststorePath = config.getString(ExecConstants.HTTP_TRUSTSTORE_PATH);

    truststorePassword = config.getString(ExecConstants.HTTP_TRUSTSTORE_PASSWORD);

      if (keystorePath.trim().length() != 0 || keystorePassword.trim().length() != 0) {
        validateKeystore = true;
        if (keystorePath.trim().length() == 0 || keystorePassword.trim().length() == 0) {
          throw new DrillException("keystore path and/or keystore password in the configuration file can't be empty");
        }

      }
    
  }

  public String getkeystorePath() {
    return keystorePath;
  }

  public String getkeystorePassword() {
    return keystorePassword;
  }

  public String gettruststorePath() {
    return truststorePath;
  }

  public String gettruststorePassword() {
    return truststorePassword;
  }
}
