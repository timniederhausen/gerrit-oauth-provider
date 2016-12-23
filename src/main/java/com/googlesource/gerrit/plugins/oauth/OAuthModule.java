package com.googlesource.gerrit.plugins.oauth;

import com.google.gerrit.extensions.annotations.Exports;
import com.google.gerrit.extensions.annotations.PluginName;
import com.google.gerrit.extensions.auth.oauth.OAuthLoginProvider;
import com.google.gerrit.server.config.PluginConfig;
import com.google.gerrit.server.config.PluginConfigFactory;
import com.google.inject.AbstractModule;
import com.google.inject.Inject;

class OAuthModule extends AbstractModule {
  private final PluginConfigFactory cfgFactory;
  private final String pluginName;

  @Inject
  OAuthModule(PluginConfigFactory cfgFactory,
      @PluginName String pluginName) {
    this.cfgFactory = cfgFactory;
    this.pluginName = pluginName;
  }

  @Override
  protected void configure() {
    PluginConfig cfg = cfgFactory.getFromGerritConfig(
        pluginName + CasOAuthService.CONFIG_SUFFIX);
    if (cfg.getString(InitOAuth.CLIENT_ID) != null) {
      bind(OAuthLoginProvider.class)
          .annotatedWith(Exports.named(CasOAuthService.CONFIG_SUFFIX))
          .to(CasOAuthLoginProvider.class);
    }
  }
}
