// Copyright (C) 2016 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.googlesource.gerrit.plugins.oauth;

import com.google.gerrit.extensions.auth.oauth.OAuthLoginProvider;
import com.google.gerrit.extensions.auth.oauth.OAuthToken;
import com.google.gerrit.extensions.auth.oauth.OAuthUserInfo;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;

import java.io.IOException;

@Singleton
public class CasOAuthLoginProvider implements OAuthLoginProvider {
  private static final String GRANT_TYPE = "grant_type";
  private static final String BY_PASSWORD = "password";

  private static final String CLIENT_ID_PARAMETER = "client_id";
  private static final String USERNAME_PARAMETER = "username";
  private static final String PASSWORD_PARAMETER = "password";

  private final CasOAuthService service;

  @Inject
  CasOAuthLoginProvider(CasOAuthService service) {
    this.service = service;
  }

  @Override
  public OAuthUserInfo login(String username, String secret)
      throws IOException {
    OAuthRequest request =
        new OAuthRequest(service.getApi().getAccessTokenVerb(),
            service.getApi().getAccessTokenEndpoint());
    request.addQuerystringParameter(GRANT_TYPE, BY_PASSWORD);
    request.addQuerystringParameter(CLIENT_ID_PARAMETER, service.getClientId());
    request.addQuerystringParameter(USERNAME_PARAMETER, username);
    request.addQuerystringParameter(PASSWORD_PARAMETER, secret);

    Response response = request.send();
    Token to =
        service.getApi().getAccessTokenExtractor().extract(response.getBody());

    return service.getUserInfo(new OAuthToken(to.getToken(),
        to.getSecret(), to.getRawResponse()));
  }
}
