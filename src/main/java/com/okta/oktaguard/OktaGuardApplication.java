package com.okta.oktaguard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
public class OktaGuardApplication {

	public static void main(String[] args) {
		SpringApplication.run(OktaGuardApplication.class, args);
	}

}
