package com.example.ex_oauth_jwt.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

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

    @GetMapping("/success")
    public String successLogin() {
        return "로그인 성공";
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }
}
