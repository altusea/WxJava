package com.github.binarywang.wxpay.config;

import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;

/**
 * @author <a href="https://github.com/ifcute">dagewang</a>
 */
@FunctionalInterface
public interface HttpClientBuilderCustomizerHC {
  void customize(HttpClientBuilder builder);
}
