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

import com.google.common.base.CharMatcher;
import com.google.gerrit.extensions.annotations.PluginName;
import com.google.gerrit.extensions.auth.oauth.OAuthServiceProvider;
import com.google.gerrit.extensions.auth.oauth.OAuthToken;
import com.google.gerrit.extensions.auth.oauth.OAuthUserInfo;
import com.google.gerrit.extensions.auth.oauth.OAuthVerifier;
import com.google.gerrit.server.OutputFormat;
import com.google.gerrit.server.config.CanonicalWebUrl;
import com.google.gerrit.server.config.PluginConfig;
import com.google.gerrit.server.config.PluginConfigFactory;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import org.eclipse.jgit.util.Base64;
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.*;
import org.scribe.oauth.OAuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Singleton
class OlympiaOAuthService implements OAuthServiceProvider {
  private static final Logger log =
      LoggerFactory.getLogger(OlympiaOAuthService.class);
  static final String CONFIG_SUFFIX = "-olympia-oauth";
  private final static String OLYMPIA_PROVIDER_PREFIX = "olympia-oauth:";
  private static final String PROTECTED_RESOURCE_URL =
      "%s/oauth2.0/profile";

  private static final String GRANT_TYPE = "grant_type";
  private static final String AUTHORIZATION_CODE = "authorization_code";

  private final String rootUrl;
  private final boolean fixLegacyUserId;
  private final String clientId;
  private final String clientSecret;
  private final String callback;
  private final OlympiaApi api;
  private final OAuthService service;

  @Inject
  OlympiaOAuthService(PluginConfigFactory cfgFactory,
      @PluginName String pluginName,
      @CanonicalWebUrl Provider<String> urlProvider) {
    PluginConfig cfg = cfgFactory.getFromGerritConfig(
        pluginName + CONFIG_SUFFIX);
    rootUrl = cfg.getString(InitOAuth.ROOT_URL);
    fixLegacyUserId = cfg.getBoolean(InitOAuth.FIX_LEGACY_USER_ID, false);
    clientId = cfg.getString(InitOAuth.CLIENT_ID);
    clientSecret = cfg.getString(InitOAuth.CLIENT_SECRET);
    api = new OlympiaApi(rootUrl);
    String canonicalWebUrl = CharMatcher.is('/').trimTrailingFrom(
        urlProvider.get()) + "/";
    callback = canonicalWebUrl + "oauth";
    service = new ServiceBuilder()
        .provider(api)
        .apiKey(clientId)
        .apiSecret(clientSecret)
        .callback(callback)
        .build();
  }

  @Override
  public OAuthUserInfo getUserInfo(OAuthToken token) throws IOException {
    final String protectedResourceUrl =
        String.format(PROTECTED_RESOURCE_URL, rootUrl);
    OAuthRequest request = new OAuthRequest(Verb.GET, protectedResourceUrl);
    request.addHeader(OAuthConstants.HEADER, "Bearer " + token.getToken());
    Response response = request.send();
    if (response.getCode() != HttpServletResponse.SC_OK) {
      throw new IOException(String.format("Status %s (%s) for request %s",
          response.getCode(), response.getBody(), request.getUrl()));
    }
    JsonElement userJson =
        OutputFormat.JSON.newGson().fromJson(response.getBody(),
            JsonElement.class);
    if (log.isDebugEnabled()) {
      log.debug("User info response: {}", response.getBody());
    }
    if (userJson.isJsonObject()) {
      JsonObject jsonObject = userJson.getAsJsonObject();
      JsonElement id = jsonObject.get("id");
      if (id == null || id.isJsonNull()) {
        throw new IOException("Response doesn't contain id field");
      }
      return new OAuthUserInfo(OLYMPIA_PROVIDER_PREFIX + id.getAsString(),
          getStringElement(jsonObject, "login"),
          getStringElement(jsonObject, "email"),
          getStringElement(jsonObject, "name"),
          fixLegacyUserId ? id.getAsString() : null);
    } else {
      throw new IOException(String.format(
          "Invalid JSON '%s': not a JSON Object", userJson));
    }
  }

  @Override
  public OAuthToken getAccessToken(OAuthVerifier rv) {
    Verifier vi = new Verifier(rv.getValue());
    return extractToken(getAccessToken(vi));
  }

  @Override
  public String getAuthorizationUrl() {
    return service.getAuthorizationUrl(null);
  }

  @Override
  public String getVersion() {
    return service.getVersion();
  }

  @Override
  public String getName() {
    return "Olympia OAuth2";
  }

  OAuthRequest makeTokenRequest() {
    OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(),
        api.getAccessTokenEndpoint());
    final String auth = clientId + ":" + clientSecret;
    request.addHeader(OAuthConstants.HEADER, "Basic " + String.valueOf(
        Base64.encodeBytes(auth.getBytes())));
    return request;
  }

  OAuthToken extractToken(String body) {
    final Token to = api.getAccessTokenExtractor().extract(body);
    return new OAuthToken(to.getToken(),
        to.getSecret(), to.getRawResponse());
  }

  private String getStringElement(JsonObject o, String name)
      throws IOException {
    JsonElement elem = o.get(name);
    if (elem == null || elem.isJsonNull())
      return null;

    return elem.getAsString();
  }

  private String getAccessToken(Verifier verifier) {
    Request request = makeTokenRequest();
    request.addBodyParameter(GRANT_TYPE, AUTHORIZATION_CODE);
    request.addBodyParameter(OAuthConstants.CODE, verifier.getValue());
    request.addBodyParameter(OAuthConstants.REDIRECT_URI, callback);
    return request.send().getBody();
  }
}
