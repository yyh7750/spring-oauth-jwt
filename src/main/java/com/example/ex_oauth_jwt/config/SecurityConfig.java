package com.example.ex_oauth_jwt.config;

import com.example.ex_oauth_jwt.config.jwt.JwtFilter;
import com.example.ex_oauth_jwt.config.jwt.JwtProvider;
import com.example.ex_oauth_jwt.config.oauth.CustomOAuth2UserService;
import com.example.ex_oauth_jwt.config.oauth.OAuth2SuccessHandler;
import com.example.ex_oauth_jwt.model.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

/**
 * packageName    : com.example.ex_oauth_jwt.config
 * fileName       : SecurityConfig
 * author         : yyh77
 * date           : 2023-08-14
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-08-14        yyh77       최초 생성
 */
@Configuration
@EnableWebSecurity // Spring Security Filter Chain 빈 추가
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService oAuth2UserService;
    private final OAuth2SuccessHandler successHandler;
    private final JwtFilter jwtFilter;
    private final CorsFilter corsFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf().disable()
                .formLogin().disable() // form login 방식 사용하지 않고 rest 방식 사용
                .httpBasic().disable() // Authorization에 username, password 활용한 방식 사용하지 않음. (jwt 활용한 Bearer 사용)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용하지 않음

                .and()

                // 인가 설정
                .authorizeRequests()
                .antMatchers("/home/**").permitAll()
                .anyRequest().permitAll()

                .and()

                // oauth login 설정
                .oauth2Login()
                .successHandler(successHandler)
                .userInfoEndpoint().userService(oAuth2UserService);

        http.addFilter(corsFilter);
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
