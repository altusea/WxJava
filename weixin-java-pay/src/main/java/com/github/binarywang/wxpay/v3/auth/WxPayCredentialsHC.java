package com.github.binarywang.wxpay.v3.auth;


import com.github.binarywang.wxpay.v3.CredentialsHC;
import com.github.binarywang.wxpay.v3.WechatPayUploadHttpPostHC;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.http.HttpEntityContainer;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.HttpRequestWrapper;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

@Slf4j
public class WxPayCredentialsHC implements CredentialsHC {
  private static final String SYMBOLS =
      "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  private static final SecureRandom RANDOM = new SecureRandom();
  protected String merchantId;
  protected Signer signer;

  public WxPayCredentialsHC(String merchantId, Signer signer) {
    this.merchantId = merchantId;
    this.signer = signer;
  }

  public String getMerchantId() {
    return merchantId;
  }

  protected long generateTimestamp() {
    return System.currentTimeMillis() / 1000;
  }

  protected String generateNonceStr() {
    char[] nonceChars = new char[32];
    for (int index = 0; index < nonceChars.length; ++index) {
      nonceChars[index] = SYMBOLS.charAt(RANDOM.nextInt(SYMBOLS.length()));
    }
    return new String(nonceChars);
  }

  @Override
  public final String getSchema() {
    return "WECHATPAY2-SHA256-RSA2048";
  }

  @Override
  public final String getToken(HttpRequestWrapper request) throws IOException, ParseException {
    String nonceStr = generateNonceStr();
    long timestamp = generateTimestamp();

    String message = buildMessage(nonceStr, timestamp, request);
    log.debug("authorization message=[{}]", message);

    Signer.SignatureResult signature = signer.sign(message.getBytes(StandardCharsets.UTF_8));

    String token = "mchid=\"" + getMerchantId() + "\","
        + "nonce_str=\"" + nonceStr + "\","
        + "timestamp=\"" + timestamp + "\","
        + "serial_no=\"" + signature.certificateSerialNumber + "\","
        + "signature=\"" + signature.sign + "\"";
    log.debug("authorization token=[{}]", token);

    return token;
  }

  protected final String buildMessage(String nonce, long timestamp, HttpRequestWrapper request)
    throws IOException, ParseException {
    URI uri = request.getUri();
    String canonicalUrl = uri.getRawPath();
    if (uri.getQuery() != null) {
      canonicalUrl += "?" + uri.getRawQuery();
    }

    String body = "";
    // PATCH,POST,PUT
    if (request.getOriginal() instanceof WechatPayUploadHttpPostHC) {
      body = ((WechatPayUploadHttpPostHC) request.getOriginal()).getMeta();
    } else if (request instanceof HttpEntityContainer) {
      body = EntityUtils.toString(((HttpEntityContainer) request).getEntity());
    }

    return request.getMethod() + "\n"
        + canonicalUrl + "\n"
        + timestamp + "\n"
        + nonce + "\n"
        + body + "\n";
  }

}
