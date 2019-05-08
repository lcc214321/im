package com.github.surpassm.im.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan({"com.github.surpassm.im.oauth2","com.github.surpassm.security"})
public class ImOauth2Application {

	public static void main(String[] args) {
		SpringApplication.run(ImOauth2Application.class, args);
	}

}
