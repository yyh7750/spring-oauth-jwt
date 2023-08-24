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

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf().disable()
                .httpBasic().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()

                .authorizeRequests()
                .antMatchers("/home/**").permitAll()
                .antMatchers("/success/**").hasRole(Role.GUEST.getRole())
                .anyRequest().authenticated()

                .and()

                .oauth2Login()
                .successHandler(successHandler)
                .userInfoEndpoint().userService(oAuth2UserService);

        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
