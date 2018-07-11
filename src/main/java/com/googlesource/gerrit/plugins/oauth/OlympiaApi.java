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

import com.google.common.io.BaseEncoding;
import com.google.gerrit.extensions.auth.oauth.OAuthToken;
import com.google.gerrit.server.OutputFormat;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.scribe.exceptions.OAuthException;
import org.scribe.model.*;
import org.scribe.utils.OAuthEncoder;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OlympiaApi {
  private static final String AUTHORIZE_URL =
      "%s/oauth2.0/authorize?response_type=code&client_id=%s&redirect_uri=%s";
  private static final String TOKEN_URL =
      "%s/oauth2.0/token";
  private static final String PROFILE_URL =
      "%s/oauth2.0/profile";

  private static final String BASIC_AUTH = "Basic";
  private static final String BEARER_AUTH = "Bearer";

  private static final String GRANT_TYPE = "grant_type";

  private static final String BY_AUTHORIZATION_CODE = "authorization_code";
  private static final String BY_PASSWORD = "password";

  private static final String USERNAME_PARAMETER = "username";
  private static final String PASSWORD_PARAMETER = "password";

  private final String rootUrl;
  private final String clientId;
  private final String clientSecret;
  private final String callback;

  public OlympiaApi(String rootUrl, String clientId, String clientSecret,
      String callback) {
    this.rootUrl = rootUrl;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.callback = callback;
  }

  public String getAuthorizationUrl() {
    return String.format(AUTHORIZE_URL, rootUrl, clientId,
        OAuthEncoder.encode(callback));
  }

  /**
   * Retrieve an access token using the "Authorization Code Grant" method of
   * RFC6749.
   *
   * @param code The authorization code that was obtained from Olympia
   * @return An access token
   */
  public OAuthToken getAccessToken(String code) throws IOException {
    final OAuthRequest request = makeTokenRequest();
    request.addBodyParameter(GRANT_TYPE, BY_AUTHORIZATION_CODE);
    request.addBodyParameter(OAuthConstants.CODE, code);
    request.addBodyParameter(OAuthConstants.REDIRECT_URI, callback);
    return extractAccessToken(submitRequest(request));
  }

  /**
   * Retrieve an access token using the
   * "Resource Owner Password Credentials Grant" method of RFC6749.
   *
   * @param username Owner's Olympia username
   * @param password Owner's Olympia password
   * @return An access token
   */
  public OAuthToken getAccessToken(final String username,
      final String password) throws IOException {
    final OAuthRequest request = makeTokenRequest();
    request.addBodyParameter(GRANT_TYPE, BY_PASSWORD);
    request.addBodyParameter(USERNAME_PARAMETER, username);
    request.addBodyParameter(PASSWORD_PARAMETER, password);
    return extractAccessToken(submitRequest(request));
  }

  /**
   * Get the raw response of the profile endpoint
   *
   * @param token The access token to authenticate with.
   * @return The raw profile endpoint content.
   * @throws IOException Thrown when encountering an unexpected response.
   */
  public String getProfile(OAuthToken token) throws IOException {
    final String profileUrl = String.format(PROFILE_URL, rootUrl);
    final OAuthRequest request = new OAuthRequest(Verb.GET, profileUrl);
    request
        .addHeader(OAuthConstants.HEADER, BEARER_AUTH + " " + token.getToken());
    return submitRequest(request);
  }

  private OAuthRequest makeTokenRequest() {
    final OAuthRequest request =
        new OAuthRequest(Verb.POST, String.format(TOKEN_URL, rootUrl));
    final String auth = clientId + ":" + clientSecret;
    final String authBase64 = BaseEncoding.base64().encode(auth.getBytes());
    request.addHeader(OAuthConstants.HEADER, BASIC_AUTH + " " + authBase64);
    return request;
  }

  private String submitRequest(Request request) throws IOException {
    final Response response = request.send();
    if (response.getCode() != HttpServletResponse.SC_OK) {
      throw new IOException(String.format("Status %s (%s) for request %s",
          response.getCode(), response.getBody(), request.getUrl()));
    }
    return response.getBody();
  }

  private OAuthToken extractAccessToken(final String response) {
    final JsonElement json = OutputFormat.JSON.newGson().fromJson(response,
        JsonElement.class);
    if (!json.isJsonObject())
      throw new OAuthException(String.format(
          "Invalid JSON '%s': not a JSON Object", json));

    final JsonObject root = json.getAsJsonObject();
    final String accessToken =
        GsonUtils.getStringElementOrThrow(root, "access_token");
    final long expiresIn =
        GsonUtils.getLongElement(root, "expires_in", Long.MAX_VALUE);

    return new OAuthToken(accessToken, "", response,
        System.currentTimeMillis() + 1000 * expiresIn,
        "oauth:olympia");
  }
}
