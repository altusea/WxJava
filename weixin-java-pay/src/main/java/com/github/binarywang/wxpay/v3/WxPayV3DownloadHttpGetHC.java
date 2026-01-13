package com.github.binarywang.wxpay.v3;

import org.apache.hc.client5.http.classic.methods.HttpGet;

import java.net.URI;

public class WxPayV3DownloadHttpGetHC extends HttpGet {

  public WxPayV3DownloadHttpGetHC(URI uri) {
    super(uri);
  }

  public WxPayV3DownloadHttpGetHC(String uri) {
    super(uri);
  }
}
