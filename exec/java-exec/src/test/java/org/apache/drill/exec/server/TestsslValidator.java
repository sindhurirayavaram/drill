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

package org.apache.drill.exec.server;

import org.apache.drill.common.exceptions.DrillException;
import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.server.rest.sslValidator;
import org.apache.drill.test.ConfigBuilder;
import org.junit.Test;

public class TestsslValidator {
  ConfigBuilder config = new ConfigBuilder();

  @Test
  public void firstTestSSLValidator() throws DrillException{

    config.put(ExecConstants.HTTP_KEYSTORE_PASSWORD, "");
    config.put(ExecConstants.HTTP_KEYSTORE_PATH, "/root");
    sslValidator sslv = new sslValidator(config.build());


  }

  @Test
  public void secondTestSSLValidator() throws DrillException{

    config.put(ExecConstants.HTTP_KEYSTORE_PASSWORD, "root");
    config.put(ExecConstants.HTTP_KEYSTORE_PATH, "");
    sslValidator sslv = new sslValidator(config.build());

  }

  @Test
  public void thirdTestSSLValidator() throws DrillException{

    config.put(ExecConstants.HTTP_KEYSTORE_PASSWORD, "root");
    config.put(ExecConstants.HTTP_KEYSTORE_PATH, "/root");
    sslValidator sslv = new sslValidator(config.build());

  }

}
