// package com.example.fiu_module.Config;

// import org.apache.kafka.clients.consumer.ConsumerConfig;
// import org.apache.kafka.common.serialization.StringDeserializer;
// import org.springframework.beans.factory.annotation.Value;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.kafka.annotation.EnableKafka;
// import org.springframework.kafka.annotation.KafkaListener;
// import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
// import org.springframework.kafka.core.ConsumerFactory;
// import org.springframework.kafka.core.DefaultKafkaConsumerFactory;

// import java.util.HashMap;
// import java.util.Map;

// @EnableKafka
// @Configuration
// public class KafkaConsumerConfig {

//     @Value("${brokerList}")
//     private String bootstrapServers;

//     @Value("${groupId}")
//     private String groupId;

//     @Bean
//     public ConsumerFactory<String, String> consumerFactory() {
//         Map<String, Object> config = new HashMap<>();
//         config.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
//         config.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
//         config.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
//         config.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
//         config.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest"); // can also be 'latest'

//         return new DefaultKafkaConsumerFactory<>(config);
//     }

//     @Bean
//     public ConcurrentKafkaListenerContainerFactory<String, String> kafkaListenerContainerFactory() {
//         ConcurrentKafkaListenerContainerFactory<String, String> factory = new ConcurrentKafkaListenerContainerFactory<>();
//         factory.setConsumerFactory(consumerFactory());
//         return factory;
//     }

//     @KafkaListener(topics = { "sib_error", "sib_response" })
//     public void consume(String message) {
//         System.out.println("Received Message: " + message);
//     }
// }
