/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

package com.facebook.react.modules.network;

import android.content.Context;
import android.os.Build;

import com.facebook.common.logging.FLog;

import java.io.File;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.annotation.Nullable;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;


import okhttp3.Cache;
import okhttp3.ConnectionSpec;
import okhttp3.OkHttpClient;
import okhttp3.TlsVersion;

/**
 * Helper class that provides the same OkHttpClient instance that will be used
 * for all networking requests.
 */
public class OkHttpClientProvider {

  // Centralized OkHttpClient for all networking requests.
  private static @Nullable OkHttpClient sClient;

  // User-provided OkHttpClient factory
  private static @Nullable OkHttpClientFactory sFactory;

  public static void setOkHttpClientFactory(OkHttpClientFactory factory) {
    sFactory = factory;
  }

  public static OkHttpClient getOkHttpClient() {
    if (sClient == null) {
      sClient = createClient();
    }
    return sClient;
  }

  public static SSLContext getSSLContext() {
    X509TrustManager xtm = new X509TrustManager() {
      @Override
      public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType)
          throws CertificateException {

      }

      @Override
      public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
          throws CertificateException {

      }

      @Override
      public X509Certificate[] getAcceptedIssuers() {
        X509Certificate[] x509Certificates = new X509Certificate[0];
        return x509Certificates;
      }
    };

    SSLContext sslContext = null;
    try {
      sslContext = SSLContext.getInstance("SSL");

      sslContext.init(null, new TrustManager[] { xtm }, new SecureRandom());

    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (KeyManagementException e) {
      e.printStackTrace();
    }

    return sslContext;
  }

  public static OkHttpClient createClient() {
    if (sFactory != null) {
      return sFactory.createNewNetworkModuleClient();
    }
    return createClientBuilder().hostnameVerifier(new HostnameVerifier() {
      @Override
      public boolean verify(String hostname, SSLSession session) {
        return true;
      }
    }).sslSocketFactory(getSSLContext().getSocketFactory()).build();
  }

  public static OkHttpClient createClient(Context context) {
    if (sFactory != null) {
      return sFactory.createNewNetworkModuleClient();
    }
    return createClientBuilder(context).build();
  }

  public static OkHttpClient.Builder createClientBuilder() {
    // No timeouts by default
    OkHttpClient.Builder client = new OkHttpClient.Builder().connectTimeout(0, TimeUnit.MILLISECONDS)
        .readTimeout(0, TimeUnit.MILLISECONDS).writeTimeout(0, TimeUnit.MILLISECONDS)
        .cookieJar(new ReactCookieJarContainer());

    try {
      Class ConscryptProvider = Class.forName("org.conscrypt.OpenSSLProvider");
      Security.insertProviderAt((Provider) ConscryptProvider.newInstance(), 1);
      return client;
    } catch (Exception e) {
      return enableTls12OnPreLollipop(client);
    }
  }

  public static OkHttpClient.Builder createClientBuilder(Context context) {
    int cacheSize = 10 * 1024 * 1024; // 10 Mo
    return createClientBuilder(context, cacheSize);
  }

  public static OkHttpClient.Builder createClientBuilder(Context context, int cacheSize) {
    OkHttpClient.Builder client = createClientBuilder();

    if (cacheSize == 0) {
      return client;
    }

    File cacheDirectory = new File(context.getCacheDir(), "http-cache");
    Cache cache = new Cache(cacheDirectory, cacheSize);

    return client.cache(cache);
  }

  /*
   * On Android 4.1-4.4 (API level 16 to 19) TLS 1.1 and 1.2 are available but not
   * enabled by default. The following method enables it.
   */
  public static OkHttpClient.Builder enableTls12OnPreLollipop(OkHttpClient.Builder client) {
    if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.KITKAT) {
      try {
        client.sslSocketFactory(new TLSSocketFactory());

        ConnectionSpec cs = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS).tlsVersions(TlsVersion.TLS_1_2)
            .build();

        List<ConnectionSpec> specs = new ArrayList<>();
        specs.add(cs);
        specs.add(ConnectionSpec.COMPATIBLE_TLS);
        specs.add(ConnectionSpec.CLEARTEXT);

        client.connectionSpecs(specs);
      } catch (Exception exc) {
        FLog.e("OkHttpClientProvider", "Error while enabling TLS 1.2", exc);
      }
    }

    return client;
  }

}
