package com.github.binarywang.wxpay.v3;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.entity.mime.HttpMultipartMode;
import org.apache.hc.client5.http.entity.mime.MultipartEntityBuilder;
import org.apache.hc.core5.http.ContentType;

import java.io.InputStream;
import java.net.URI;
import java.net.URLConnection;

public class WechatPayUploadHttpPostHC extends HttpPost {

  private String meta;

  private WechatPayUploadHttpPostHC(URI uri, String meta) {
    super(uri);

    this.meta = meta;
  }

  public String getMeta() {
    return meta;
  }

  public static class Builder {

    private String fileName;
    private String fileSha256;
    private InputStream fileInputStream;
    private ContentType fileContentType;
    private URI uri;

    public Builder(URI uri) {
      this.uri = uri;
    }

    public Builder withImage(String fileName, String fileSha256, InputStream inputStream) {
      this.fileName = fileName;
      this.fileSha256 = fileSha256;
      this.fileInputStream = inputStream;

      String mimeType = URLConnection.guessContentTypeFromName(fileName);
      if (mimeType == null) {
        // guess this is a video uploading
        this.fileContentType = ContentType.APPLICATION_OCTET_STREAM;
      } else {
        this.fileContentType = ContentType.create(mimeType);
      }
      return this;
    }

    public WechatPayUploadHttpPostHC build() {
      if (fileName == null || fileSha256 == null || fileInputStream == null) {
        throw new IllegalArgumentException("缺少待上传图片文件信息");
      }

      if (uri == null) {
        throw new IllegalArgumentException("缺少上传图片接口URL");
      }

      String meta = String.format("{\"filename\":\"%s\",\"sha256\":\"%s\"}", fileName, fileSha256);
      WechatPayUploadHttpPostHC request = new WechatPayUploadHttpPostHC(uri, meta);

      MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create();
      entityBuilder.setMode(HttpMultipartMode.EXTENDED)
        .addBinaryBody("file", fileInputStream, fileContentType, fileName)
        .addTextBody("meta", meta, ContentType.APPLICATION_JSON);

      request.setEntity(entityBuilder.build());
      request.addHeader("Accept", ContentType.APPLICATION_JSON.toString());

      return request;
    }

    /**
     * 平台收付通（注销申请）-图片上传-图片上传
     * https://pay.weixin.qq.com/docs/partner/apis/ecommerce-cancel/media/upload-media.html
     * @return WechatPayUploadHttpPost
     */
    public WechatPayUploadHttpPostHC buildEcommerceAccount() {
      if (fileName == null || fileSha256 == null || fileInputStream == null) {
        throw new IllegalArgumentException("缺少待上传图片文件信息");
      }

      if (uri == null) {
        throw new IllegalArgumentException("缺少上传图片接口URL");
      }

      String meta = String.format("{\"file_name\":\"%s\",\"file_digest\":\"%s\"}", fileName, fileSha256);
      WechatPayUploadHttpPostHC request = new WechatPayUploadHttpPostHC(uri, meta);

      MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create();
      entityBuilder.setMode(HttpMultipartMode.EXTENDED)
        .addBinaryBody("file", fileInputStream, fileContentType, fileName)
        .addTextBody("meta", meta, ContentType.APPLICATION_JSON);

      request.setEntity(entityBuilder.build());
      request.addHeader("Accept", ContentType.APPLICATION_JSON.toString());

      return request;
    }
  }
}
