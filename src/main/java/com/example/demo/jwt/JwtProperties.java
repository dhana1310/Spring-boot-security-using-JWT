package com.example.demo.jwt;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "jwt.config")
public class JwtProperties {

    private String secretKey;
    private int validityInDays;
    private String issuer;
    private String authoritiesKey;
    private String tokenPrefix;
    private String tokenPrefixForTokenGeneration;
}
