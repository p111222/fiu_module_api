// package com.example.fiu_module.service;

// import java.util.HashMap;
// import java.util.Map;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.kafka.core.KafkaTemplate;
// import org.springframework.stereotype.Service;

// @Service
// public class KafkaProducerService {

//     private static final String TOPIC = "sib";

//     @Autowired
//     private KafkaTemplate<String, Object> kafkaTemplate;

//     public void sendMessage(Object message, boolean isError) {
//         Map<String, Object> messagePayload = new HashMap<>();
//         messagePayload.put("isError", isError);
//         messagePayload.put("message", message);

//         kafkaTemplate.send(TOPIC, messagePayload);
//     }
// }

