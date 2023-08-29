package com.example.ex_oauth_jwt.config.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * packageName    : com.example.ex_oauth_jwt.config.auth
 * fileName       : PasswordEncoder
 * author         : yyh77
 * date           : 2023-08-29
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-08-29        yyh77       최초 생성
 */
@Component
public class PasswordEncoderBean {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
