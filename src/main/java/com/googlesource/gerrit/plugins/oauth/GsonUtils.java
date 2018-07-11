package com.googlesource.gerrit.plugins.oauth;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.scribe.exceptions.OAuthException;

/**
 * Utilities for handling JSON objects
 */
public class GsonUtils {
  public static String getStringElement(JsonObject o, String name) {
    final JsonElement elem = o.get(name);
    if (elem == null || elem.isJsonNull())
      return null;
    return elem.getAsString();
  }

  public static String getStringElementOrThrow(JsonObject o, String name) throws
      OAuthException {
    final String s = getStringElement(o, name);
    if (s == null)
      throw new OAuthException(String.format(
          "Invalid JSON '%s': no %s", o.toString(), name));
    return s;
  }

  public static long getLongElement(JsonObject o, String name, long def) {
    final JsonElement elem = o.get(name);
    if (elem == null || elem.isJsonNull())
      return def;
    return elem.getAsLong();
  }
}
