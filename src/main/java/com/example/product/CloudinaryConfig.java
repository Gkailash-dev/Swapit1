package com.example.product;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
@Configuration
public class CloudinaryConfig {
    @Value("${cloudinary.cloud-name}")
    private String cloudName;

    @Value("${cloudinary.api-key}")
    private String apiKey;

    @Value("${cloudinary.api-secret}")
    private String apiSecret;
    @Bean
    public Cloudinary cloudinary() {
        return new Cloudinary(ObjectUtils.asMap(
                "cloud_name", cloudName,     // 🔹 replace with your Cloudinary cloud name
                "api_key", apiKey,           // 🔹 replace with your Cloudinary API key
                "api_secret", apiSecret     // 🔹 replace with your Cloudinary API secret
        ));
    }
}
