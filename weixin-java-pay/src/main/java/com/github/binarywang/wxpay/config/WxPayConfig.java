package com.github.binarywang.wxpay.config;

import com.github.binarywang.wxpay.exception.WxPayException;
import com.github.binarywang.wxpay.util.ResourcesUtils;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RegExUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.ssl.SSLContexts;

import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * 微信支付配置
 *
 * @author Binary Wang (<a href="https://github.com/binarywang">...</a>)
 */
@Data
@Slf4j
public class WxPayConfig {
  private static final String DEFAULT_PAY_BASE_URL = "https://api.mch.weixin.qq.com";
  private static final String PROBLEM_MSG = "证书文件【%s】有问题，请核实！";
  private static final String NOT_FOUND_MSG = "证书文件【%s】不存在，请核实！";
  private static final String CERT_NAME_P12 = "p12证书";

  /**
   * 微信支付接口请求地址域名部分.
   */
  private String apiHostUrl = DEFAULT_PAY_BASE_URL;

  /**
   * http请求连接超时时间.
   */
  private int httpConnectionTimeout = 5000;

  /**
   * http请求数据读取等待时间.
   */
  private int httpTimeout = 10000;

  /**
   * 公众号appid.
   */
  private String appId;
  /**
   * 服务商模式下的子商户公众账号ID.
   */
  private String subAppId;
  /**
   * 商户号.
   */
  protected String mchId;
  /**
   * 商户密钥.
   */
  private String mchKey;
  /**
   * 企业支付密钥.
   */
  private String entPayKey;
  /**
   * 服务商模式下的子商户号.
   */
  private String subMchId;
  /**
   * 微信支付异步回调地址，通知url必须为直接可访问的url，不能携带参数.
   */
  private String notifyUrl;
  /**
   * 退款结果异步回调地址，通知url必须为直接可访问的url，不能携带参数.
   */
  private String refundNotifyUrl;
  /**
   * 交易类型.
   * <pre>
   * JSAPI--公众号支付
   * NATIVE--原生扫码支付
   * APP--app支付
   * </pre>
   */
  private String tradeType;
  /**
   * 签名方式.
   * 有两种HMAC_SHA256 和MD5
   *
   * @see com.github.binarywang.wxpay.constant.WxPayConstants.SignType
   */
  private String signType;
  private SSLContext sslContext;
  /**
   * p12证书base64编码
   */
  private String keyString;
  /**
   * p12证书文件的绝对路径或者以classpath:开头的类路径.
   */
  private String keyPath;

  /**
   * apiclient_key.pem证书base64编码
   */
  private String privateKeyString;
  /**
   * apiclient_key.pem证书文件的绝对路径或者以classpath:开头的类路径.
   */
  private String privateKeyPath;

  /**
   * apiclient_cert.pem证书base64编码
   */
  private String privateCertString;
  /**
   * apiclient_cert.pem证书文件的绝对路径或者以classpath:开头的类路径.
   */
  private String privateCertPath;

  /**
   * apiclient_key.pem证书文件内容的字节数组.
   */
  protected byte[] privateKeyContent;

  /**
   * apiclient_cert.pem证书文件内容的字节数组.
   */
  protected byte[] privateCertContent;

  /**
   * 公钥ID
   */
  protected String publicKeyId;

  /**
   * pub_key.pem证书base64编码
   */
  private String publicKeyString;

  /**
   * pub_key.pem证书文件的绝对路径或者以classpath:开头的类路径.
   */
  private String publicKeyPath;

  /**
   * pub_key.pem证书文件内容的字节数组.
   */
  protected byte[] publicKeyContent;
  /**
   * apiV3 秘钥值.
   */
  private String apiV3Key;

  /**
   * apiV3 证书序列号值
   */
  protected String certSerialNo;
  /**
   * 微信支付分serviceId
   */
  private String serviceId;

  /**
   * 微信支付分回调地址
   */
  private String payScoreNotifyUrl;


  /**
   * 微信支付分授权回调地址
   */
  private String payScorePermissionNotifyUrl;

  /**
   * HTTP连接池最大连接数，默认20
   */
  protected int maxConnTotal = 20;

  /**
   * HTTP连接池每个路由的最大连接数，默认10
   */
  protected int maxConnPerRoute = 10;
  /**
   * 私钥信息
   */
  protected PrivateKey privateKey;

  /**
   * 证书自动更新时间差(分钟)，默认一分钟
   */
  private int certAutoUpdateTime = 60;

  /**
   * p12证书文件内容的字节数组.
   */
  private byte[] keyContent;
  /**
   * 微信支付是否使用仿真测试环境.
   * 默认不使用
   */
  private boolean useSandboxEnv = false;

  /**
   * 是否将接口请求日志信息保存到threadLocal中.
   * 默认不保存
   */
  private boolean ifSaveApiData = false;

  private String httpProxyHost;
  private Integer httpProxyPort;
  private String httpProxyUsername;
  private String httpProxyPassword;



  /**
   * 是否将全部v3接口的请求都添加Wechatpay-Serial请求头，默认不添加
   */
  private boolean strictlyNeedWechatPaySerial = false;

  /**
   * 是否完全使用公钥模式(用以微信从平台证书到公钥的灰度切换)，默认不使用
   */
  protected boolean fullPublicKeyModel = false;

  /**
   * 返回所设置的微信支付接口请求地址域名.
   *
   * @return 微信支付接口请求地址域名
   */
  public String getApiHostUrl() {
    if (StringUtils.isEmpty(this.apiHostUrl)) {
      return DEFAULT_PAY_BASE_URL;
    }

    return this.apiHostUrl;
  }

  /**
   * 初始化ssl.
   *
   * @return the ssl context
   * @throws WxPayException the wx pay exception
   */
  public SSLContext initSSLContext() throws WxPayException {
    if (StringUtils.isBlank(this.getMchId())) {
      throw new WxPayException("请确保商户号mchId已设置");
    }

    try (InputStream inputStream = this.loadConfigInputStream(this.keyString, this.getKeyPath(),
      this.keyContent, CERT_NAME_P12)) {
      KeyStore keystore = KeyStore.getInstance("PKCS12");
      char[] partnerId2charArray = this.getMchId().toCharArray();
      keystore.load(inputStream, partnerId2charArray);
      this.sslContext = SSLContexts.custom().loadKeyMaterial(keystore, partnerId2charArray).build();
      return this.sslContext;
    } catch (Exception e) {
      throw new WxPayException("证书文件有问题，请核实！", e);
    }

  }

  /**
   * 初始化一个WxPayHttpProxy对象
   *
   * @return 返回封装的WxPayHttpProxy对象。如未指定代理主机和端口，则默认返回null
   */
  protected WxPayHttpProxy getWxPayHttpProxy() {
    if (StringUtils.isNotBlank(this.getHttpProxyHost()) && this.getHttpProxyPort() > 0) {
      return new WxPayHttpProxy(getHttpProxyHost(), getHttpProxyPort(), getHttpProxyUsername(), getHttpProxyPassword());
    }
    return null;
  }

  /**
   * 从指定参数加载输入流
   *
   * @param configString  证书内容进行Base64加密后的字符串
   * @param configPath    证书路径
   * @param configContent 证书内容的字节数组
   * @param certName      证书的标识
   * @return 输入流
   * @throws WxPayException 异常
   */
  protected InputStream loadConfigInputStream(String configString, String configPath, byte[] configContent,
                                              String certName) throws WxPayException {
    if (configContent != null) {
      return new ByteArrayInputStream(configContent);
    }

    if (StringUtils.isNotEmpty(configString)) {
      // 判断是否为PEM格式的字符串（包含-----BEGIN和-----END标记）
      if (isPemFormat(configString)) {
        // PEM格式直接转为字节流，让PemUtils处理
        configContent = configString.getBytes(StandardCharsets.UTF_8);
      } else {
        // 尝试Base64解码
        try {
          byte[] decoded = Base64.getDecoder().decode(configString);
          // 检查解码后的内容是否为PEM格式（即用户传入的是base64编码的完整PEM文件）
          String decodedString = new String(decoded, StandardCharsets.UTF_8);
          if (isPemFormat(decodedString)) {
            // 解码后是PEM格式，使用解码后的内容
            configContent = decoded;
          } else {
            // 解码后不是PEM格式，可能是：
            // 1. p12证书的二进制内容 - 应该返回解码后的二进制数据
            // 2. 私钥/公钥的纯base64内容（不含PEM头尾） - 应该返回原始字符串，让PemUtils处理
            // 通过certName区分：p12证书使用解码后的数据，其他情况返回原始字符串
            if (CERT_NAME_P12.equals(certName)) {
              configContent = decoded;
            } else {
              // 对于私钥/公钥/证书，返回原始字符串字节，让PemUtils处理base64解码
              configContent = configString.getBytes(StandardCharsets.UTF_8);
            }
          }
        } catch (IllegalArgumentException e) {
          // Base64解码失败，可能是格式不正确，抛出异常
          throw new WxPayException(String.format("【%s】的Base64格式不正确", certName), e);
        }
      }
      return new ByteArrayInputStream(configContent);
    }

    if (StringUtils.isBlank(configPath)) {
      throw new WxPayException(String.format("请确保【%s】的文件地址【%s】存在", certName, configPath));
    }

    return this.loadConfigInputStream(configPath);
  }

  /**
   * 判断字符串是否为PEM格式（包含-----BEGIN和-----END标记）
   *
   * @param content 要检查的字符串
   * @return 是否为PEM格式
   */
  private boolean isPemFormat(String content) {
    return content != null && content.contains("-----BEGIN") && content.contains("-----END");
  }


  /**
   * 从配置路径 加载配置 信息（支持 classpath、本地路径、网络url）
   *
   * @param configPath 配置路径
   * @return .
   * @throws WxPayException .
   */
  private InputStream loadConfigInputStream(String configPath) throws WxPayException {
    String fileHasProblemMsg = String.format(PROBLEM_MSG, configPath);
    String fileNotFoundMsg = String.format(NOT_FOUND_MSG, configPath);

    final String prefix = "classpath:";
    InputStream inputStream;
    if (configPath.startsWith(prefix)) {
      String path = RegExUtils.removeFirst(configPath, prefix);
      if (!path.startsWith("/")) {
        path = "/" + path;
      }

      try {
        inputStream = ResourcesUtils.getResourceAsStream(path);
        if (inputStream == null) {
          throw new WxPayException(fileNotFoundMsg);
        }

        return inputStream;
      } catch (Exception e) {
        throw new WxPayException(fileNotFoundMsg, e);
      }
    }

    if (configPath.startsWith("http://") || configPath.startsWith("https://")) {
      try {
        inputStream = new URL(configPath).openStream();
        if (inputStream == null) {
          throw new WxPayException(fileNotFoundMsg);
        }
        return inputStream;
      } catch (IOException e) {
        throw new WxPayException(fileNotFoundMsg, e);
      }
    } else {
      try {
        File file = new File(configPath);
        if (!file.exists()) {
          throw new WxPayException(fileNotFoundMsg);
        }
        //使用Files.newInputStream打开公私钥文件，会存在无法释放句柄的问题
        //return Files.newInputStream(file.toPath());
        return new FileInputStream(file);
      } catch (IOException e) {
        throw new WxPayException(fileHasProblemMsg, e);
      }
    }
  }

  /**
   * 分解p12证书文件
   */
  protected Object[] p12ToPem() {
    String key = getMchId();
    if (StringUtils.isBlank(key) ||
      (StringUtils.isBlank(this.getKeyPath()) && this.keyContent == null && StringUtils.isBlank(this.keyString))) {
      return null;
    }

    // 分解p12证书文件
    try (InputStream inputStream = this.loadConfigInputStream(this.keyString, this.getKeyPath(),
      this.keyContent, CERT_NAME_P12)) {
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      keyStore.load(inputStream, key.toCharArray());

      String alias = keyStore.aliases().nextElement();
      PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, key.toCharArray());

      Certificate certificate = keyStore.getCertificate(alias);
      X509Certificate x509Certificate = (X509Certificate) certificate;
      return new Object[]{privateKey, x509Certificate};
    } catch (Exception e) {
      log.error("加载p12证书时发生异常", e);
    }

    return null;

  }

}
