package com.galapea.belajar.springsecoauth2jwt;

import com.galapea.belajar.springsecoauth2jwt.config.RsaKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeyProperties.class)
public class SpringSecOauth2jwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecOauth2jwtApplication.class, args);
	}

}
