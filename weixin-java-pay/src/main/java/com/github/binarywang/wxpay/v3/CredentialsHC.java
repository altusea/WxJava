package com.github.binarywang.wxpay.v3;

import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.message.HttpRequestWrapper;

import java.io.IOException;

public interface CredentialsHC {

  String getSchema();

  String getToken(HttpRequestWrapper request) throws IOException, ParseException;
}
