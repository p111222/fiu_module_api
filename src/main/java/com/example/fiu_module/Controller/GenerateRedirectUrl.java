package com.example.fiu_module.Controller;

// import com.example.fiu_module.Config.KafkaProducer;
import com.example.fiu_module.modal.Domain;
import com.example.fiu_module.repository.DomainRepository;
import com.example.fiu_module.service.Encryptdecrypt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
// import org.slf4j.Logger;
// import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.security.MessageDigest;
import java.util.Collections;

@RestController
@RequestMapping("/api/redirect")
public class GenerateRedirectUrl {

    // private static final Logger logger =
    // LoggerFactory.getLogger(GenerateRedirectUrl.class);

    @Autowired
    private RestTemplate restTemplate;

    // @Autowired
    // private DomainRepository domainRepository;

    // @Autowired
    // private KafkaProducerService kafkaProducerService;

    // @Autowired
    // private KafkaProducer kafkaProducer;

    @Autowired
    private Encryptdecrypt encryptDecrypt;

    // private String errorTopic = "aa_redirection_error";
    // private String errorTopicExternalApi = "external_api_error";
    // private String responseTopic = "aa_redirection_response";

    @Value("${webSecretKey}")
    private String webSecretKey;

    // @Value("${externalApiUrl}")
    // private String apiUrl;

    @PostMapping(value = "/generateredirecturl", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, String>> generateRedirectUrl(
            @RequestParam("aaId") String aaId,
            // @RequestParam("reqdate") String reqdate,
            // @RequestParam(value = "requestorType", required = false) String requestorTypeStr,
            @RequestParam("redirectUrl") String redirectUrl,
            @RequestParam("srcRef") String[] srcRef,
            @RequestParam("sessionId") String sessionId,
            @RequestParam("txnid") String txnid,
            // @RequestParam(value = "userid", required = false) String userid,
            @RequestParam(value = "fipid", required = false) List<String> fipid,
            @RequestParam(value = "email", required = false) String email,
            @RequestParam(value = "pan", required = false) String pan,
            @RequestParam(value = "dob", required = false) String dob) throws ParseException {

        // Extract the part after "@" from the aaId
        String[] aaIdParts = aaId.split("@");
        if (aaIdParts.length < 2) {
            String error = "Invalid aaId format. It should contain '@' followed by the entity.";
            // kafkaProducer.sendMessage(errorTopic, error);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.singletonMap("error", error));
        }
        String entityHandle = aaIdParts[1];

        // Make a request to the external API with the extracted entity handle
        // String apiUrl = "https://10.12.218.62:8446/cr/fiu/redirecturl";
        String apiUrl = "http://api.kriate.co.in:8344/redirection/stub/geturl";
        HttpHeaders apiHeaders = new HttpHeaders();
        apiHeaders.add("entityHandle", "@" + entityHandle);

        HttpEntity<Void> apiRequest = new HttpEntity<>(apiHeaders);

        // Send the request and handle the response
        ResponseEntity<Map> apiResponse;
        try {
            apiResponse = restTemplate.exchange(apiUrl, HttpMethod.GET, apiRequest, Map.class);
        } catch (Exception e) {
            String error = "Error calling external API: " + e.getMessage();
            // kafkaProducer.sendMessage(errorTopicExternalApi, error);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.singletonMap("error", error));
        }

        // String webviewUrl="https://aa-uat-onemoney.in";
        String webviewUrl;
        if (apiResponse.getBody() != null && apiResponse.getBody().get("webviewurl") != null) {
            webviewUrl = apiResponse.getBody().get("webviewurl").toString();
        } else {
            String error = "Invalid response from external API";
            // kafkaProducer.sendMessage(errorTopicExternalApi, error);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.singletonMap("error",
                    error));
        }
        // Validate mandatory parameters
        if (txnid == null || txnid.isEmpty()) {
            String error = "Transaction ID (txnid) is required";
            // kafkaProducer.sendMessage(errorTopic, error);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.singletonMap("error", error));
        }
        if (sessionId == null || sessionId.isEmpty()) {
            String error = "Session ID (sessionid) is required";
            // kafkaProducer.sendMessage(errorTopic, error);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.singletonMap("error", error));
        }
        if (redirectUrl == null || redirectUrl.isEmpty()) {
            String error = "Redirect URL is required";
            // kafkaProducer.sendMessage(errorTopic, error);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.singletonMap("error", error));
        }
        if (srcRef == null || srcRef.length == 0) {
            String error = "Source Reference (srcref) is required";
            // kafkaProducer.sendMessage(errorTopic, error);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.singletonMap("error",
                    error));
        }
        if (aaId == null || aaId.isEmpty()) {
            String error = "Unique requestor identifier (aaId) is required";
            // kafkaProducer.sendMessage(errorTopic, error);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.singletonMap("error", error));
        }
        // if (reqdate == null || reqdate.isEmpty()) {
        //     String error = "Request date (reqdate) is required";
        //     // kafkaProducer.sendMessage(errorTopic, error);
        //     return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", error));
        // }

        // Validate requestorType if provided
        // RequestorType requestorType = null;
        // if (requestorTypeStr != null && !requestorTypeStr.isEmpty()) {
        //     try {
        //         requestorType = RequestorType.valueOf(requestorTypeStr.toUpperCase());
        //     } catch (IllegalArgumentException e) {
        //         String error = "Invalid requestor type. Valid values are: FIU, LSP.";
        //         // kafkaProducer.sendMessage(errorTopic, error);
        //         return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", error));
        //     }
        // }

        // Validate and parse the reqdate parameter
        // System.out.println("reqdatetime" + reqdate);
        DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("ddMMyyyyHHmmss").withZone(ZoneOffset.UTC);
        String reqdate = dateFormatter.format(LocalDateTime.now(ZoneOffset.UTC));
        // LocalDateTime reqdate = LocalDateTime.now(ZoneOffset.UTC);
        System.out.println("reqDate:-"+reqdate);
        LocalDateTime reqDateTime;
        try {
        reqDateTime = LocalDateTime.parse(reqdate, DateTimeFormatter.ofPattern("ddMMyyyyHHmmss"));
        } catch (DateTimeParseException e) {
        String error = "Invalid reqdate format";
        // kafkaProducer.sendMessage(errorTopic, error);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.singletonMap("error",
        error));
        }

        LocalDateTime currentTime = LocalDateTime.now(ZoneOffset.UTC);

        // Ensure the request date is not in the future
        if (reqDateTime.isAfter(currentTime)) {
        String error = "Request date cannot be in the future";
        // kafkaProducer.sendMessage(errorTopic, error);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.singletonMap("error",
        error));
        }

        // if (reqdate.isAfter(currentTime)) {
        //     String error = "Request date cannot be in the future";
        //     // kafkaProducer.sendMessage(errorTopic, error);
        //     return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", error));
        // }

        // long timeDiff = ChronoUnit.SECONDS.between(reqDateTime, currentTime);
        long timeDiff = ChronoUnit.SECONDS.between(reqDateTime, currentTime);

        // Ensure the request date is within the acceptable time window
        if (timeDiff > 180) {
            String error = "Request time exceeded";
            // kafkaProducer.sendMessage(errorTopic, error);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.singletonMap("error", error));
        }

        // Generate a unique ID for FIU
        // UUID fiuId = UUID.randomUUID();
        String fiuId = "sibl-uat-fiu";

        // String webSecretKey = "xC??HfRDqL&XkA3J";
        String encryptedFi = encryptDecrypt.xorEncrypt(fiuId, reqdate);

        // Set up headers for the HTTP request
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/x-www-form-urlencoded");

        String url = "http://localhost:8080/api/redirect/encrypt";

        // Create headers for the request
        HttpHeaders requestHeaders = new HttpHeaders();
        requestHeaders.add("Content-Type", "application/x-www-form-urlencoded");

        // Create the request payload for the encryption service
        // Map<String, String> encryptionPayload = new HashMap<>();
        // String encryptedRequestorType;
        // MultiValueMap<String, String> encryptionPayload = new
        // LinkedMultiValueMap<>();
        // // encryptionPayload.add("data", requestorType != null ?
        // requestorType.toString() : "");
        // if (requestorType != null && !requestorType.toString().isEmpty()) {
        // encryptionPayload.add("data", requestorType.toString());
        // } else {
        // encryptedRequestorType = null;
        // }
        // encryptionPayload.add("salt", reqdate);

        // HttpEntity<MultiValueMap<String, String>> encryptionRequestEntity = new
        // HttpEntity<>(encryptionPayload,
        // requestHeaders);
        // // Send the request to the encryption service and handle the response
        // String encryptionServiceUrl = "http://localhost:8080/api/redirect/encrypt";
        // ResponseEntity<String> encryptionServiceResponse;
        // try {
        // encryptionServiceResponse = restTemplate.postForEntity(encryptionServiceUrl,
        // encryptionRequestEntity,
        // String.class);
        // } catch (Exception e) {
        // String error = "Error: " + e.getMessage();
        // // kafkaProducer.sendMessage(errorTopic, error);
        // return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
        // .body(Map.of("error", error));
        // }

        // // Extract the encrypted requestor type from the response

        // try {
        // encryptedRequestorType = encryptionServiceResponse.getBody();
        // System.out.println("requestorType" + encryptedRequestorType);
        // } catch (Exception e) {
        // String error = "Unexpected response format from encryption service";
        // // kafkaProducer.sendMessage(errorTopic, error);
        // return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
        // .body(Map.of("error", error));
        // }

        String encryptedRequestorType = null; // Initialize as null
        MultiValueMap<String, String> encryptionPayload = new LinkedMultiValueMap<>();

        // Only add 'data' to encryptionPayload if requestorType is valid
        // if (requestorType != null && !requestorType.toString().isEmpty()) {
        //     encryptionPayload.add("data", requestorType.toString());
        //     encryptionPayload.add("salt", reqdate); // Add salt only when data is present

        //     // Create the HTTP entity only if there's data to encrypt
        //     HttpEntity<MultiValueMap<String, String>> encryptionRequestEntity = new HttpEntity<>(encryptionPayload,
        //             requestHeaders);

        //     // Send the request to the encryption service and handle the response
        //     String encryptionServiceUrl = "http://localhost:8080/api/redirect/encrypt";
        //     ResponseEntity<String> encryptionServiceResponse;
        //     try {
        //         encryptionServiceResponse = restTemplate.postForEntity(encryptionServiceUrl, encryptionRequestEntity,
        //                 String.class);

        //         // Extract the encrypted requestor type from the response
        //         encryptedRequestorType = encryptionServiceResponse.getBody();
        //         System.out.println("requestorType: " + encryptedRequestorType);
        //     } catch (Exception e) {
        //         String error = "Error: " + e.getMessage();
        //         // kafkaProducer.sendMessage(errorTopic, error);
        //         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
        //                 .body(Map.of("error", error));
        //     }
        // } else {
        //     System.out.println("No requestorType provided, skipping encryption.");
        // }

        // Create another request payload for the encryption service
        StringBuilder encReqBuilder = new StringBuilder(
                String.format("txnid=%s&sessionid=%s&srcref=%s&userid=%s&redirect=%s&fi=%s",
                        txnid, sessionId, String.join(",", srcRef), aaId, redirectUrl, encryptedFi));

        System.out.println("fipid" + fipid);
        System.out.println("srcref: " + Arrays.toString(srcRef));
        // Check for optional parameters and append them if available
        if (fipid != null && !fipid.isEmpty()) {
            encReqBuilder.append("&fipid=").append(String.join(",", fipid));
        }
        if (email != null && !email.isEmpty()) {
            encReqBuilder.append("&email=").append(email);
        }
        if (dob != null && !dob.isEmpty()) {
            // System.out.println("hiii");
            encReqBuilder.append("&dob=").append(dob);
        }
        if (pan != null && !pan.isEmpty()) {
            encReqBuilder.append("&pan=").append(pan);
        }

        // Convert the StringBuilder to a string
        String encReq = encReqBuilder.toString();

        // Map<String, String> map1 = new HashMap<>();
        MultiValueMap<String, String> map1 = new LinkedMultiValueMap<>();
        map1.add("data", encReq);
        map1.add("salt", reqdate);

        HttpEntity<MultiValueMap<String, String>> req1 = new HttpEntity<>(map1, headers);

        // Send the second request to the encryption service and handle the response
        ResponseEntity<String> response;
        try {
            response = restTemplate.postForEntity(url, req1, String.class);
        } catch (Exception e) {
            String error = "Error: " + e.getMessage();
            // kafkaProducer.sendMessage(errorTopic, error);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.singletonMap("error", error));
        }

        // Extract the encrypted request from the response
        String encryptedReq;
        try {
            encryptedReq = response.getBody();
            System.out.println("ecreq" + encryptedReq);
        } catch (Exception e) {
            String error = "Unexpected response format from encryption service";
            // kafkaProducer.sendMessage(errorTopic, error);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.singletonMap("error", error));
        }

        String baseUrl = String.format("%s?fi=%s&reqdate=%s&ecreq=%s", webviewUrl, encryptedFi, reqdate, encryptedReq);

        // if (encryptedRequestorType != null) {
        //     baseUrl += String.format("&requestorType=%s", encryptedRequestorType);
        // }

        // Use aaId instead of aa if that's the correct variable
        String aaWebviewUrl = baseUrl;

        Map<String, String> responseMap = new HashMap<>();
        responseMap.put("redirectUrl", aaWebviewUrl);

        // kafkaProducer.sendMessage(responseTopic, responseMap.toString());
        return ResponseEntity.ok(responseMap);
    }

    // Enum for requestor types
    public enum RequestorType {
        FIU,
        LSP
    }

    @PostMapping("/showresult")
    public ResponseEntity<Map<String, String>> showResult(@RequestBody Map<String, String> request) {

        String fi = request.get("fi");
        String resDate = request.get("resDate");
        String ecres = request.get("ecres");
        // String requestorType = request.get("requestorType");

        String decryptUrl = "http://localhost:8080/api/redirect/decrypt";

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/x-www-form-urlencoded");

        String decryptedFi = encryptDecrypt.xorDecrypt(fi, webSecretKey);

        MultiValueMap<String, String> decryptRequest = new LinkedMultiValueMap<>();
        decryptRequest.add("data", ecres);
        decryptRequest.add("salt", resDate);

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(decryptRequest, headers);

        ResponseEntity<String> response;
        // ResponseEntity<String> requestorTypeResponse;

        try {
            response = restTemplate.postForEntity(decryptUrl, httpEntity, String.class);

        //     decryptRequest.clear();
            // decryptRequest.add("data", requestorType);
            // decryptRequest.add("salt", resDate);
        //     HttpEntity<MultiValueMap<String, String>> requestorTypeHttpEntity = new HttpEntity<>(decryptRequest,
        //             headers);
        //     requestorTypeResponse = restTemplate.postForEntity(decryptUrl, requestorTypeHttpEntity, String.class);
        } catch (Exception e) {
            String error = "Error: " + e.getMessage();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.singletonMap("error", error));
        }

        String decryptedResponse;
        // String decryptedRequestorType;
        try {
            decryptedResponse = response.getBody();
            // decryptedRequestorType = requestorTypeResponse.getBody();
        } catch (Exception e) {
            String error = "Unexpected response format from decryption service";
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.singletonMap("error", error));
        }

        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("decryptedResponse", decryptedResponse);
        responseBody.put("decryptedFi", decryptedFi);
        // responseBody.put("decryptedRequestorType", decryptedRequestorType);

        return ResponseEntity.ok(responseBody);
    }

    @PostMapping(value = "/encrypt", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<String> Encrypt(
            @RequestParam("data") String data,
            @RequestParam("salt") String salt) {

        // Check if both data and salt are provided
        if (data == null || salt == null) {
            String error = "Both 'data' and 'salt' must be provided.";
            // kafkaProducer.sendMessage(errorTopic, error);
            return ResponseEntity.badRequest().body(error);
        }

        String encryptedResult;
        try {
            // Perform encryption
            encryptedResult = encryptDecrypt.encryption(data, salt);
            // kafkaProducer.sendMessage(responseTopic, encryptedResult);
            return ResponseEntity.ok(encryptedResult);
        } catch (Exception e) {
            String error = "Error during encryption: " + e.getMessage();
            // kafkaProducer.sendMessage(errorTopic, error);
            return ResponseEntity.status(500).body(error);
        }
    }

    // Endpoint to handle decryption requests
    @PostMapping(value = "/decrypt", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<String> Decrypt(
            @RequestParam("data") String data,
            @RequestParam("salt") String salt) {

        // Check if both data and salt are provided
        if (data == null || salt == null) {
            String error = "Both 'data' and 'salt' must be provided.";
            // kafkaProducer.sendMessage(errorTopic, error);
            return ResponseEntity.badRequest().body(error);
        }

        String decryptedResult;
        try {
            // Perform decryption
            decryptedResult = encryptDecrypt.decryption(data, salt);
            // kafkaProducer.sendMessage(responseTopic, decryptedResult);
            return ResponseEntity.ok(decryptedResult);
        } catch (Exception e) {
            String error = "Error during decryption: " + e.getMessage();
            // kafkaProducer.sendMessage(errorTopic, error);
            return ResponseEntity.status(500).body(error);
        }
    }

}
