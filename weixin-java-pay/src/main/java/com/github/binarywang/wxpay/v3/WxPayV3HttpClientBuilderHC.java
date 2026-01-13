package com.github.binarywang.wxpay.v3;


import com.github.binarywang.wxpay.v3.auth.PrivateKeySigner;
import com.github.binarywang.wxpay.v3.auth.WxPayCredentials;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.http.impl.execchain.ClientExecChain;

import java.security.PrivateKey;

public class WxPayV3HttpClientBuilderHC extends HttpClientBuilder {
  private Credentials credentials;
  private Validator validator;

  static final String OS = System.getProperty("os.name") + "/" + System.getProperty("os.version");
  static final String VERSION = System.getProperty("java.version");

  private WxPayV3HttpClientBuilderHC() {
    super();

    String userAgent = String.format(
        "WechatPay-Apache-HttpClient/%s (%s) Java/%s",
        getClass().getPackage().getImplementationVersion(),
      OS,
        VERSION == null ? "Unknown" : VERSION);
    setUserAgent(userAgent);
  }

  public static WxPayV3HttpClientBuilderHC create() {
    return new WxPayV3HttpClientBuilderHC();
  }

  public WxPayV3HttpClientBuilderHC withMerchant(String merchantId, String serialNo, PrivateKey privateKey) {
    this.credentials =
        new WxPayCredentials(merchantId, new PrivateKeySigner(serialNo, privateKey));
    return this;
  }

  public WxPayV3HttpClientBuilderHC withCredentials(Credentials credentials) {
    this.credentials = credentials;
    return this;
  }

  public WxPayV3HttpClientBuilderHC withValidator(Validator validator) {
    this.validator = validator;
    return this;
  }

  @Override
  public CloseableHttpClient build() {
    if (credentials == null) {
      throw new IllegalArgumentException("缺少身份认证信息");
    }
    if (validator == null) {
      throw new IllegalArgumentException("缺少签名验证信息");
    }

    return super.build();
  }

  @Override
  protected ClientExecChain decorateProtocolExec(final ClientExecChain requestExecutor) {
    return new SignatureExec(this.credentials, this.validator, requestExecutor);
  }
}
