package com.example.fiu_module.Config;

// import org.apache.kafka.clients.producer.ProducerConfig;
// import org.apache.kafka.common.serialization.StringSerializer;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.kafka.core.DefaultKafkaProducerFactory;
// import org.springframework.kafka.core.KafkaTemplate;
// import org.springframework.kafka.core.ProducerFactory;
// import org.springframework.kafka.support.serializer.JsonSerializer;

// import java.util.HashMap;
// import java.util.Map;

// @Configuration
// public class KafkaProducerConfig {

//     @Bean
//     public ProducerFactory<String, Object> producerFactory() {
//         Map<String, Object> configProps = new HashMap<>();
//         configProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "3.108.54.64:9096");
//         configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
//         configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
//         configProps.put(ProducerConfig.ACKS_CONFIG, "all");
//         configProps.put(ProducerConfig.RETRIES_CONFIG, 10);
//         configProps.put(ProducerConfig.LINGER_MS_CONFIG, 1);
//         configProps.put(ProducerConfig.BUFFER_MEMORY_CONFIG, 33554432);
//         configProps.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, 60000);
//         return new DefaultKafkaProducerFactory<>(configProps);
//     }

//     @Bean
//     public KafkaTemplate<String, Object> kafkaTemplate() {
//         return new KafkaTemplate<>(producerFactory());
//     }

// }

// import java.util.HashMap;
// import java.util.Map;

// import org.apache.kafka.clients.producer.ProducerConfig;
// import org.apache.kafka.common.serialization.StringSerializer;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.beans.factory.annotation.Value;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.kafka.core.DefaultKafkaProducerFactory;
// import org.springframework.kafka.core.KafkaTemplate;
// import org.springframework.kafka.core.ProducerFactory;

// @Configuration
// public class KafkaProducer {

//     @Value("${brokerList}")
//     private String brokerList;

//     @Autowired
//     private KafkaTemplate<String, String> kafkaTemplate;

//     @Bean
//     public ProducerFactory<String, String> producerFactory() {
//         Map<String, Object> configProps = new HashMap<>();
//         configProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, brokerList);
//         configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
//         configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class); // Change to StringSerializer
//         configProps.put(ProducerConfig.ACKS_CONFIG, "all");
//         configProps.put(ProducerConfig.RETRIES_CONFIG, 10);
//         configProps.put(ProducerConfig.LINGER_MS_CONFIG, 1);
//         configProps.put(ProducerConfig.BUFFER_MEMORY_CONFIG, 33554432);
//         configProps.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, 60000);
//         return new DefaultKafkaProducerFactory<>(configProps);
//     }

//     @Bean
//     public KafkaTemplate<String, String> kafkaTemplate() {
//         return new KafkaTemplate<>(producerFactory());
//     }

//     public void sendMessage(String topic, String record) {
//         try {
//             kafkaTemplate.send(topic, record);
//         } catch (Exception e) {
//             System.out.println("Error Producing the records in Topic: " + e.getMessage());
//         }
//     }
// }
