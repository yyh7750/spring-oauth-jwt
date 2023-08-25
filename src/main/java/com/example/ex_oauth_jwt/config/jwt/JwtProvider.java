package com.example.ex_oauth_jwt.config.jwt;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import java.util.Base64;
import java.util.Date;

/**
 * packageName    : com.example.ex_oauth_jwt.config.jwt
 * fileName       : JwtService
 * author         : yyh77
 * date           : 2023-08-14
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-08-14        yyh77       최초 생성
 */
@Slf4j
@Service
public class JwtProvider {

    // 유효기간 설정. 액세스 토큰 : 10분, 리프레쉬 토큰 : 3주
//    private long tokenPeriod = 1000L * 60L * 10L;
    private long tokenPeriod = 1000L * 60L * 1L;
//    private long refreshPeriod = 1000L * 60L * 60L * 24L * 30L * 3L;
    private long refreshPeriod = 1000L * 60L * 5L;
    private String secretKey = "secret-key";

    @PostConstruct
    public void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public Token createToken(String uid, String role) {
        Claims claims = Jwts.claims().setSubject(uid); // 토큰 제목을 uid로 설정
        claims.put("role", role);

        Date now = new Date();

        return new Token(
                Jwts.builder()
                        .setClaims(claims)
                        .setIssuedAt(now) // 발행시간
                        .setExpiration(new Date(now.getTime() + tokenPeriod)) // 만료시간 설정
                        .signWith(SignatureAlgorithm.HS256, secretKey) // 알고리즘, 시크릿키로 서명
                        .compact()
                ,
                Jwts.builder()
                        .setClaims(claims)
                        .setIssuedAt(now) // 발행시간
                        .setExpiration(new Date(now.getTime() + refreshPeriod)) // 만료시간 설정
                        .signWith(SignatureAlgorithm.HS256, secretKey) // 알고리즘, 시크릿키로 서명
                        .compact()
        );
    }

    public String generateAccessToken(String uid, String role) {
        return createToken(uid, role).getAccessToken();
    }

    public String generateRefreshToken(String uid, String role) {
        return createToken(uid, role).getRefreshToken();
    }

    public Token generateToken(String uid, String role) {
        String accessToken = generateAccessToken(uid, role);
        String refreshToken = generateRefreshToken(uid, role);

        return new Token(accessToken, refreshToken);
    }

    public boolean verifyToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) { //Token이 만료된 경우 Exception이 발생한다.
            log.error("Token Expired");
            return false;
        } catch (JwtException e) { //Token이 변조된 경우 Exception이 발생한다.
            log.error("Token Error");
            return false;
        }
    }

    public String getUid(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    public Cookie sendRefreshToken(String refreshToken) {
        // 쿠키를 생성하며 리프레시 토큰을 저장한다.
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setPath("/"); // 쿠키의 유효 경로 설정. 루트 경로일 경우 모든 사이트에서 접근 가능.
        cookie.setMaxAge(1000 * 60 * 60 * 24 * 30 * 3); // 유효기간 : 리프레시 토큰과 동일한 3주.
        cookie.setHttpOnly(true); // javascript에서 접근할 수 없도록 설정
        cookie.setSecure(true); // Https에서만 접근 허용
        return cookie;
    }
}
