package com.example.ex_oauth_jwt.config.jwt;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * packageName    : com.example.ex_oauth_jwt.config.jwt
 * fileName       : Token
 * author         : yyh77
 * date           : 2023-08-22
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-08-22        yyh77       최초 생성
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Token {

    private String accessToken;
    private String refreshToken;
}
