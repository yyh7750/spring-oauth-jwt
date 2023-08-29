package com.example.ex_oauth_jwt.controller;

import com.example.ex_oauth_jwt.config.jwt.JwtProvider;
import com.example.ex_oauth_jwt.config.jwt.Token;
import com.example.ex_oauth_jwt.model.LoginForm;
import com.example.ex_oauth_jwt.model.Role;
import com.example.ex_oauth_jwt.model.User;
import com.example.ex_oauth_jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

/**
 * packageName    : com.example.ex_oauth_jwt.controller
 * fileName       : AuthController
 * author         : yyh77
 * date           : 2023-08-15
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-08-15        yyh77       최초 생성
 */
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final JwtProvider jwtProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final BCryptPasswordEncoder passwordEncoder;

    @GetMapping("/success")
    public String successLogin() {
        return "로그인 성공";
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @PostMapping("/join")
    public ResponseEntity<?> join(@RequestBody LoginForm loginForm) {
        Optional<User> byEmail = userRepository.findByEmail(loginForm.getEmail());
        String answer = null;
        if (byEmail.isPresent()) {
            answer = "이미 가입된 회원입니다";
        } //
        else {
            Token tokens = jwtProvider.generateToken(loginForm.getEmail(), Role.GUEST.getRole());
            userRepository.save(
                    User.builder()
                            .email(loginForm.getEmail())
                            .password(passwordEncoder.encode(loginForm.getPassword()))
                            .nickname("ㅁㄴㅇㄹ")
                            .refreshToken(tokens.getRefreshToken())
                            .role(Role.GUEST)
                            .build());
            answer = loginForm.getEmail();

            jwtProvider.sendRefreshToken(tokens.getRefreshToken());
        }
        return new ResponseEntity<>(answer, HttpStatus.CREATED);
    }

    @PostMapping("/auth/login")
    public String authLogin(@RequestBody LoginForm loginForm) {

        System.out.println("==========================");
        System.out.println("==========================");
        System.out.println("==========================");

        // 1. Login ID/PW 를 기반으로 Authentication 객체 생성
        // 이때 authentication 는 인증 여부를 확인하는 authenticated 값이 false
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginForm.getEmail(), loginForm.getPassword());

        // 2. 실제 검증 (사용자 비밀번호 체크)이 이루어지는 부분
        // authenticate 매서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드가 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 3. 토큰 발급
        String uid = authentication.getName();
        String accessToken = jwtProvider.generateAccessToken(uid, Role.GUEST.getRole());

        return accessToken;
    }
}
