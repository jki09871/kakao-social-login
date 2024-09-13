package com.kakao.social.login;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication
public class KakaoSocialLoginApplication {

    public static void main(String[] args) {
        SpringApplication.run(KakaoSocialLoginApplication.class, args);
    }

}
