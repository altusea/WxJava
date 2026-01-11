package com.github.binarywang.wxpay.v3;

import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;

import java.io.IOException;

public interface ValidatorHC {
  boolean validate(CloseableHttpResponse response) throws IOException;
}
