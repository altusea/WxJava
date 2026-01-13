package com.github.binarywang.wxpay.config;

import com.github.binarywang.wxpay.exception.WxPayException;
import com.github.binarywang.wxpay.util.HttpProxyUtils;
import com.github.binarywang.wxpay.v3.WxPayV3HttpClientBuilder;
import com.github.binarywang.wxpay.v3.auth.Verifier;
import com.github.binarywang.wxpay.v3.auth.WxPayValidator;
import com.github.binarywang.wxpay.v3.util.PemUtils;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;

import javax.net.ssl.SSLContext;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Optional;

@Getter
@Setter
public class WxPayConfigApacheHttp extends WxPayConfig {

  /**
   * v3接口下证书检验对象，通过改对象可以获取到X509Certificate，进一步对敏感信息加密
   * <a href="https://wechatpay-api.gitbook.io/wechatpay-api-v3/qian-ming-zhi-nan-1/min-gan-xin-xi-jia-mi">文档</a>
   */
  private Verifier verifier;

  private CloseableHttpClient apiV3HttpClient;

  /**
   * 用于普通支付接口的可复用HttpClient，使用连接池
   */
  private CloseableHttpClient httpClient;

  /**
   * 用于需要SSL证书的支付接口的可复用HttpClient，使用连接池
   */
  private CloseableHttpClient sslHttpClient;

  /**
   * 支持扩展httpClientBuilder
   */
  private HttpClientBuilderCustomizer httpClientBuilderCustomizer;
  private HttpClientBuilderCustomizer apiV3HttpClientBuilderCustomizer;

  @SneakyThrows
  public Verifier getVerifier() {
    if (verifier == null) {
      //当改对象为null时，初始化api v3的请求头
      initApiV3HttpClient();
    }
    return verifier;
  }

  /**
   * 初始化api v3请求头 自动签名验签
   * 方法参照 <a href="https://github.com/wechatpay-apiv3/wechatpay-apache-httpclient">微信支付官方api项目</a>
   *
   * @return org.apache.http.impl.client.CloseableHttpClient
   * @author doger.wang
   * @throws WxPayException 微信支付异常
   */
  public CloseableHttpClient initApiV3HttpClient() throws WxPayException {
    if (StringUtils.isBlank(this.getApiV3Key())) {
      throw new WxPayException("请确保apiV3Key值已设置");
    }
    try {
      PrivateKey merchantPrivateKey = null;
      PublicKey publicKey = null;

      // 不使用完全公钥模式时，同时兼容平台证书和公钥
      X509Certificate certificate = null;
      // 尝试从p12证书中加载私钥和证书
      Object[] objects = this.p12ToPem();
      if (objects != null) {
        merchantPrivateKey = (PrivateKey) objects[0];
        certificate = (X509Certificate) objects[1];
        this.certSerialNo = certificate.getSerialNumber().toString(16).toUpperCase();
      }
      if (certificate == null && StringUtils.isBlank(this.getCertSerialNo()) && (StringUtils.isNotBlank(this.getPrivateCertPath()) || StringUtils.isNotBlank(this.getPrivateCertString()) || this.getPrivateCertContent() != null)) {
        try (InputStream certInputStream = this.loadConfigInputStream(this.getPrivateCertString(), this.getPrivateCertPath(),
          this.privateCertContent, "privateCertPath")) {
          certificate = PemUtils.loadCertificate(certInputStream);
        }
        this.certSerialNo = certificate.getSerialNumber().toString(16).toUpperCase();
      }

      if (StringUtils.isNotBlank(this.getPublicKeyString()) || StringUtils.isNotBlank(this.getPublicKeyPath()) || this.publicKeyContent != null) {
        if (StringUtils.isBlank(this.getPublicKeyId())) {
          throw new WxPayException("请确保和publicKeyId配套使用");
        }
        try (InputStream pubInputStream =
               this.loadConfigInputStream(this.getPublicKeyString(), this.getPublicKeyPath(),
                 this.publicKeyContent, "publicKeyPath")) {
          publicKey = PemUtils.loadPublicKey(pubInputStream);
        }
      }

      // 加载api私钥
      if (merchantPrivateKey == null && (StringUtils.isNotBlank(this.getPrivateKeyPath()) || StringUtils.isNotBlank(this.getPrivateKeyString()) || null != this.privateKeyContent)) {
        try (InputStream keyInputStream = this.loadConfigInputStream(this.getPrivateKeyString(), this.getPrivateKeyPath(),
          this.privateKeyContent, "privateKeyPath")) {
          merchantPrivateKey = PemUtils.loadPrivateKey(keyInputStream);
        }
      }

      //构造Http Proxy正向代理
      WxPayHttpProxy wxPayHttpProxy = getWxPayHttpProxy();

      // 构造证书验签器
      Verifier certificatesVerifier;
      if (this.fullPublicKeyModel) {
        // 使用完全公钥模式时，只加载公钥相关配置，避免下载平台证书使灰度切换无法达到100%覆盖
        if (publicKey == null) {
          throw new WxPayException("完全公钥模式下，请确保公钥配置（publicKeyPath/publicKeyString/publicKeyContent）及publicKeyId已设置");
        }
        certificatesVerifier = VerifierBuilder.buildPublicCertVerifier(this.publicKeyId, publicKey);
      } else {
        certificatesVerifier = VerifierBuilder.build(
          this.getCertSerialNo(), this.getMchId(), this.getApiV3Key(), merchantPrivateKey, wxPayHttpProxy,
          this.getCertAutoUpdateTime(), this.getApiHostUrl(), this.getPublicKeyId(), publicKey);
      }

      WxPayV3HttpClientBuilder wxPayV3HttpClientBuilder = WxPayV3HttpClientBuilder.create()
        .withMerchant(mchId, certSerialNo, merchantPrivateKey)
        .withValidator(new WxPayValidator(certificatesVerifier));
      //初始化V3接口正向代理设置
      HttpProxyUtils.initHttpProxy(wxPayV3HttpClientBuilder, wxPayHttpProxy);

      // 提供自定义wxPayV3HttpClientBuilder的能力
      Optional.ofNullable(apiV3HttpClientBuilderCustomizer).ifPresent(e -> {
        e.customize(wxPayV3HttpClientBuilder);
      });
      CloseableHttpClient httpClient = wxPayV3HttpClientBuilder.build();

      this.apiV3HttpClient = httpClient;
      this.verifier = certificatesVerifier;
      this.privateKey = merchantPrivateKey;

      return httpClient;
    } catch (WxPayException e) {
      throw e;
    } catch (Exception e) {
      throw new WxPayException("v3请求构造异常！", e);
    }
  }

  /**
   * 初始化使用连接池的HttpClient
   *
   * @return CloseableHttpClient
   * @throws WxPayException 初始化异常
   */
  public CloseableHttpClient initHttpClient() throws WxPayException {
    if (this.httpClient != null) {
      return this.httpClient;
    }

    // 创建连接池管理器
    PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
    connectionManager.setMaxTotal(this.maxConnTotal);
    connectionManager.setDefaultMaxPerRoute(this.maxConnPerRoute);

    // 创建HttpClient构建器
    org.apache.http.impl.client.HttpClientBuilder httpClientBuilder = HttpClients.custom()
      .setConnectionManager(connectionManager);

    // 配置代理
    configureProxy(httpClientBuilder);

    // 提供自定义httpClientBuilder的能力
    Optional.ofNullable(httpClientBuilderCustomizer).ifPresent(e -> {
      e.customize(httpClientBuilder);
    });

    this.httpClient = httpClientBuilder.build();
    return this.httpClient;
  }

  /**
   * 初始化使用连接池且支持SSL的HttpClient
   *
   * @return CloseableHttpClient
   * @throws WxPayException 初始化异常
   */
  public CloseableHttpClient initSslHttpClient() throws WxPayException {
    if (this.sslHttpClient != null) {
      return this.sslHttpClient;
    }

    // 初始化SSL上下文
    SSLContext sslContext = this.getSslContext();
    if (null == sslContext) {
      sslContext = this.initSSLContext();
    }

    // 创建支持SSL的连接池管理器
    SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
      sslContext,
      new DefaultHostnameVerifier()
    );

    Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder
      .<ConnectionSocketFactory>create()
      .register("https", sslsf)
      .register("http", PlainConnectionSocketFactory.getSocketFactory())
      .build();
    PoolingHttpClientConnectionManager connectionManager =
      new PoolingHttpClientConnectionManager(socketFactoryRegistry);

    // PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
    connectionManager.setMaxTotal(this.maxConnTotal);
    connectionManager.setDefaultMaxPerRoute(this.maxConnPerRoute);

    // 创建HttpClient构建器，配置SSL
    org.apache.http.impl.client.HttpClientBuilder httpClientBuilder = HttpClients.custom()
      .setConnectionManager(connectionManager)
      .setSSLSocketFactory(new SSLConnectionSocketFactory(sslContext, new DefaultHostnameVerifier()));

    // 配置代理
    configureProxy(httpClientBuilder);

    // 提供自定义httpClientBuilder的能力
    Optional.ofNullable(httpClientBuilderCustomizer).ifPresent(e -> {
      e.customize(httpClientBuilder);
    });

    this.sslHttpClient = httpClientBuilder.build();
    return this.sslHttpClient;
  }

  /**
   * 配置HTTP代理
   *
   * @param httpClientBuilder HttpClient构建器
   */
  private void configureProxy(org.apache.http.impl.client.HttpClientBuilder httpClientBuilder) {
    if (StringUtils.isNotBlank(this.getHttpProxyHost()) && this.getHttpProxyPort() > 0) {
      if (StringUtils.isEmpty(this.getHttpProxyUsername())) {
        this.setHttpProxyUsername("whatever");
      }

      // 使用代理服务器 需要用户认证的代理服务器
      CredentialsProvider provider = new BasicCredentialsProvider();
      provider.setCredentials(new AuthScope(this.getHttpProxyHost(), this.getHttpProxyPort()),
        new UsernamePasswordCredentials(this.getHttpProxyUsername(), this.getHttpProxyPassword()));
      httpClientBuilder.setDefaultCredentialsProvider(provider)
        .setProxy(new HttpHost(this.getHttpProxyHost(), this.getHttpProxyPort()));
    }
  }

}
