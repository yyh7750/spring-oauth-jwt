package com.example.ex_oauth_jwt.config.oauth;

import com.example.ex_oauth_jwt.config.jwt.JwtProvider;
import com.example.ex_oauth_jwt.config.jwt.Token;
import com.example.ex_oauth_jwt.model.Role;
import com.example.ex_oauth_jwt.model.User;
import com.example.ex_oauth_jwt.model.UserDTO;
import com.example.ex_oauth_jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * packageName    : com.example.ex_oauth_jwt.config.oauth
 * fileName       : OAuth2SuccessHandler
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
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;
    private final UserRepository userRepository;
    private final String redirectUrl = "http://localhost:8080/home/";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        UserDTO userDTO = UserDTO.of(oAuth2User);

        User guest = new User();
        User user = userRepository.findByEmail(userDTO.getEmail()).orElse(guest);

        Token tokens = new Token();

        // 최초 로그인 시
        if (user.equals(guest)) {

            // 원래는 유저 정보를 먼저 저장한 후에 토큰을 발급하여 레디스에 리프레시 토큰을 저장하는게 맞는 흐름.
            // rdb에 리프레시 토큰을 저장하기 때문에 토큰 발행을 먼저 진행하였음.
            tokens = jwtProvider.generateToken(userDTO.getEmail(), Role.GUEST.getRole());

            log.info("최초 로그인. 회원가입 진행");
            user = userRepository.save(User.of(userDTO, tokens.getRefreshToken()));
        }
        // 이미 가입한 회원일 경우
        else {
            // Role로 사용자의 페이지 이동 로직을 위해서라면 if문을 사용하여 Role 검사를 먼저 진행한다.
//            if (user.getRole().equals(Role.USER)) {
//                // 엑세스 토큰에 권한을 Role.USER 로 생성
//            }
            
            // 엑세스 토큰 발급. 테스트용이기 때문에 Role.GUEST 로 생성
            String accessToken = jwtProvider.generateAccessToken(userDTO.getEmail(), Role.GUEST.getRole());
            String refreshToken = user.getRefreshToken();
            log.info("로그인 시도한 사용자의 리프레시 토큰 : {}", refreshToken);

            // 리프레시 토큰이 유요하다면 그대로 사용.
            if (refreshToken != null && jwtProvider.verifyToken(refreshToken)) {
                log.info("회원 로그인.");
                tokens = tokens.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
            }
            // 유효하지 않다면 재발행
            else {
                log.info("회원 로그인. 리프레시 토큰 만료로 인한 재발급");
                tokens = jwtProvider.generateToken(userDTO.getEmail(), Role.GUEST.getRole());
            }
        }

        log.info("====== Token info : {} ======", tokens);

        String targetUrl = sendAccessToken(tokens.getAccessToken());
        Cookie cookie = jwtProvider.sendRefreshToken(tokens.getRefreshToken());

        response.setHeader("Authorization", "Bearer-" + tokens.getAccessToken());
        response.addCookie(cookie);

        log.info("redirect uri : {}", redirectUrl);
        log.info("target uri : {}", targetUrl);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    private String sendAccessToken(String accessToken) {
        // 강제 리다이렉트 시 request와 response가 모두 초기화 되기 때문에 url의 파라미터로 엑세스 토큰을 넘겨준다.
        return UriComponentsBuilder.fromUriString(redirectUrl)
                .queryParam("Authorization", "Bearer-" + accessToken)
                .build().toUriString();
    }
}
