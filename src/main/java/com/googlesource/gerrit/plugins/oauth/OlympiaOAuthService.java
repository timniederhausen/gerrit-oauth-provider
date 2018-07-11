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
import com.google.gerrit.extensions.auth.oauth.*;
import com.google.gerrit.reviewdb.client.AccountExternalId;
import com.google.gerrit.server.OutputFormat;
import com.google.gerrit.server.config.CanonicalWebUrl;
import com.google.gerrit.server.config.PluginConfig;
import com.google.gerrit.server.config.PluginConfigFactory;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import org.scribe.exceptions.OAuthException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

@Singleton
class OlympiaOAuthService implements OAuthServiceProvider, OAuthLoginProvider {
  private static final Logger log =
      LoggerFactory.getLogger(OlympiaOAuthService.class);
  static final String CONFIG_SUFFIX = "-olympia-oauth";

  private final OlympiaApi api;

  @Inject
  OlympiaOAuthService(PluginConfigFactory cfgFactory,
      @PluginName String pluginName,
      @CanonicalWebUrl Provider<String> urlProvider) {
    PluginConfig cfg = cfgFactory.getFromGerritConfig(
        pluginName + CONFIG_SUFFIX);
    String canonicalWebUrl = CharMatcher.is('/').trimTrailingFrom(
        urlProvider.get()) + "/";
    api = new OlympiaApi(cfg.getString(InitOAuth.ROOT_URL),
        cfg.getString(InitOAuth.CLIENT_ID),
        cfg.getString(InitOAuth.CLIENT_SECRET),
        canonicalWebUrl + "oauth");
  }

  @Override
  public OAuthUserInfo getUserInfo(OAuthToken token) throws IOException {
    final String body = api.getProfile(token);
    if (log.isDebugEnabled())
      log.debug("User info response: {}", body);

    JsonElement userJson =
        OutputFormat.JSON.newGson().fromJson(body, JsonElement.class);
    if (!userJson.isJsonObject()) {
      throw new IOException(String.format(
          "Invalid JSON '%s': not a JSON Object", userJson));
    }

    final JsonObject jsonObject = userJson.getAsJsonObject();
    final String login =
        GsonUtils.getStringElementOrThrow(jsonObject, "login");

    return new OAuthUserInfo(AccountExternalId.SCHEME_EXTERNAL + login,
        login,
        GsonUtils.getStringElement(jsonObject, "email"),
        GsonUtils.getStringElement(jsonObject, "name"),
        null);
  }

  @Override
  public OAuthToken getAccessToken(OAuthVerifier rv) {
    try {
      return api.getAccessToken(rv.getValue());
    } catch (IOException e) {
      throw new OAuthException("I/O Error", e);
    }
  }

  @Override
  public String getAuthorizationUrl() {
    return api.getAuthorizationUrl();
  }

  @Override
  public String getVersion() {
    return "2.0";
  }

  @Override
  public String getName() {
    return "Olympia OAuth2";
  }

  // OAuthLoginProvider

  @Override
  public OAuthUserInfo login(String username, String secret)
      throws IOException {
    return getUserInfo(api.getAccessToken(username, secret));
  }
}
