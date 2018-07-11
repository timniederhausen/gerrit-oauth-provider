package com.googlesource.gerrit.plugins.oauth;

import com.google.gerrit.server.OutputFormat;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.Token;

public class OlympiaAccessTokenExtractor implements AccessTokenExtractor {

  @Override
  public Token extract(String response) {
    final JsonElement json = OutputFormat.JSON.newGson().fromJson(response,
        JsonElement.class);
    if (!json.isJsonObject())
      throw new OAuthException(String.format(
          "Invalid JSON '%s': not a JSON Object", json));

    final JsonObject jsonObject = json.getAsJsonObject();
    final JsonElement accessToken = jsonObject.get("access_token");
    if (accessToken ==  null || accessToken.isJsonNull())
      throw new OAuthException(String.format(
          "Invalid JSON '%s': no access_token", json));
    return new Token(accessToken.getAsString(), "", response);
  }
}
