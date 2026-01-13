package com.github.binarywang.wxpay.v3.auth;


import com.github.binarywang.wxpay.v3.ValidatorHC;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * @author spvycf & F00lish
 */
@Slf4j
public class WxPayValidatorHC implements ValidatorHC {
  private final Verifier verifier;

  public WxPayValidatorHC(Verifier verifier) {
    this.verifier = verifier;
  }

  @Override
  public final boolean validate(CloseableHttpResponse response) throws IOException, ParseException {
    if (!ContentType.APPLICATION_JSON.getMimeType().equals(ContentType.parse(String.valueOf(response.getFirstHeader(
      "Content-Type").getValue())).getMimeType())) {
      return true;
    }
    Header serialNo = response.getFirstHeader("Wechatpay-Serial");
    Header sign = response.getFirstHeader("Wechatpay-Signature");
    Header timestamp = response.getFirstHeader("Wechatpay-TimeStamp");
    Header nonce = response.getFirstHeader("Wechatpay-Nonce");

    // todo: check timestamp
    if (timestamp == null || nonce == null || serialNo == null || sign == null) {
      return false;
    }

    String message = buildMessage(response);
    return verifier.verify(serialNo.getValue(), message.getBytes(StandardCharsets.UTF_8), sign.getValue());
  }

  protected final String buildMessage(CloseableHttpResponse response) throws IOException, ParseException {
    String timestamp = response.getFirstHeader("Wechatpay-TimeStamp").getValue();
    String nonce = response.getFirstHeader("Wechatpay-Nonce").getValue();

    String body = getResponseBody(response);
    return timestamp + "\n"
      + nonce + "\n"
      + body + "\n";
  }

  protected final String getResponseBody(CloseableHttpResponse response) throws IOException, ParseException {
    HttpEntity entity = response.getEntity();

    return (entity != null && entity.isRepeatable()) ? EntityUtils.toString(entity) : "";
  }
}
