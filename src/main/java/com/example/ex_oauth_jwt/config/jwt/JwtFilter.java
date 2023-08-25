package com.example.ex_oauth_jwt.config.jwt;

import com.example.ex_oauth_jwt.model.Role;
import com.example.ex_oauth_jwt.model.User;
import com.example.ex_oauth_jwt.model.UserDTO;
import com.example.ex_oauth_jwt.repository.UserRepository;
import io.jsonwebtoken.*;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

/**
 * packageName    : com.example.ex_oauth_jwt.config.jwt
 * fileName       : JwtFilter
 * author         : yyh77
 * date           : 2023-08-14
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-08-14        yyh77       최초 생성
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter extends GenericFilterBean {

    private final JwtProvider jwtProvider;
    private final UserRepository userRepository;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        log.info("----- JWT filter call -----");

        String token = parseBearerToken(request);

        log.info("Access Token : {}", token);

        // 토큰이 유효할 경우
        if (token != null && jwtProvider.verifyToken(token)) {
            log.info("----- 엑세스 토큰 유효 -----");
            Authentication authentication = getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("set Authentication to security context for '{}', uri = {}", authentication.getName(), ((HttpServletRequest) request).getRequestURI());
        }
        // 엑세스 토큰이 만료된 경우
        else if (token != null && !jwtProvider.verifyToken(token)) {
            // 쿠키에 저장된 리프레시 토큰 찾기
            String refreshToken = getCookieRefreshToken((HttpServletRequest) request);
            log.info("====== Cookie saved refreshToken : {} ======", refreshToken);

            // 쿠키에 저장된 리프레시 토큰으로 디비(또는 캐시)에 저장된 리프레시 토큰 가져오기
            User loginUser = userRepository.findByRefreshToken(refreshToken).orElseThrow();
            String savedRefreshToken = loginUser.getRefreshToken();

            // 쿠키에 있는 리프레시 토큰과 디비에 있는 리프레시 토큰이 같고, 유효하다면 엑세스 토큰 재발급
            if (refreshToken != null && refreshToken.equals(savedRefreshToken) && jwtProvider.verifyToken(refreshToken)) {
                String accessToken = jwtProvider.generateAccessToken(loginUser.getEmail(), Role.GUEST.getRole());

                ((HttpServletResponse) response).setHeader("Authorization", "Bearer-" + accessToken);
                Authentication authentication = getAuthentication(accessToken);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("리프레시 토큰 유효, 엑세스 토큰 재발급");
                log.info("set Authentication to security context for '{}', uri = {}", authentication.getName(), ((HttpServletRequest) request).getRequestURI());
            }
            // 리프레시 토큰이 일치하지 않거나 유효하지 않다면 엑세스, 리프레시 토큰 재발급
            else if (refreshToken != null && (!refreshToken.equals(savedRefreshToken) || !jwtProvider.verifyToken(refreshToken))) {
                Token tokens = jwtProvider.generateToken(loginUser.getEmail(), Role.GUEST.getRole());

                // 새로 발급된 리프레시 토큰 저장 및 쿠키로 전송
                // todo : 변경이 안되고 있음. 변경감지가 필요
                loginUser.setRefreshToken(tokens.getRefreshToken());
                jwtProvider.sendRefreshToken(tokens.getRefreshToken());

                // 헤더에 엑세스 토큰 넣기
                ((HttpServletResponse) response).setHeader("Authorization", "Bearer-" + tokens.getAccessToken());

                Authentication authentication = getAuthentication(tokens.getAccessToken());
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("리프레시 토큰 재발급, 엑세스 토큰 재발급. refresh : {}", tokens.getRefreshToken());
                log.info("set Authentication to security context for '{}', uri = {}", authentication.getName(), ((HttpServletRequest) request).getRequestURI());
            }
        } //
        else {
            log.info("no valid JWT token found, uri: {}", ((HttpServletRequest) request).getRequestURI());
        }

        chain.doFilter(request, response);
    }

    private String getCookieRefreshToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        System.out.println();
        System.out.println(Arrays.toString(cookies));
        System.out.println();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                String name = cookie.getName();
                String value = cookie.getValue();
                if (name.equals("refreshToken")) {
                    return value;
                }
            }
        }
        return null;
    }

    public Authentication getAuthentication(String token) {

        String email = jwtProvider.getUid(token);

        UserDTO userDTO = UserDTO.builder()
                .email(email)
                .nickname("")
                .build();

        return new UsernamePasswordAuthenticationToken(userDTO, null,
                Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private String parseBearerToken(ServletRequest request) {

        String bearerToken = ((HttpServletRequest) request).getHeader("Authorization");

        if (bearerToken != null && bearerToken.startsWith("Bearer-")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
