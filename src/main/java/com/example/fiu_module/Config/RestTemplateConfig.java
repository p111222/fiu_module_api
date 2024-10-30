package com.example.fiu_module.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class RestTemplateConfig {

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

}


// import org.springframework.boot.web.client.RestTemplateBuilder;
// import org.springframework.web.client.RestTemplate;

// import javax.net.ssl.*;
// import java.security.cert.X509Certificate;

// @Configuration
// public class RestTemplateConfig {

//     @Bean
//     public RestTemplate restTemplate(RestTemplateBuilder builder) throws Exception {
//         // Disable SSL verification
//         SSLContext sslContext = SSLContext.getInstance("TLS");
//         TrustManager[] trustManagers = new TrustManager[]{
//             new X509TrustManager() {
//                 @Override
//                 public void checkClientTrusted(X509Certificate[] chain, String authType) {
//                 }

//                 @Override
//                 public void checkServerTrusted(X509Certificate[] chain, String authType) {
//                 }

//                 @Override
//                 public X509Certificate[] getAcceptedIssuers() {
//                     return new X509Certificate[0];
//                 }
//             }
//         };

//         sslContext.init(null, trustManagers, new java.security.SecureRandom());

//         HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
//         HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

//         return builder.build(); // Return the RestTemplate with SSL disabled
//     }
// }

