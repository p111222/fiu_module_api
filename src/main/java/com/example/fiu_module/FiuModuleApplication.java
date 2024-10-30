package com.example.fiu_module;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

// @SpringBootApplication
@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class })
public class FiuModuleApplication {

	public static void main(String[] args) {
		SpringApplication.run(FiuModuleApplication.class, args);
	}

}
