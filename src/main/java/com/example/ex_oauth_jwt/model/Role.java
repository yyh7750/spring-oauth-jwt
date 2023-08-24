package com.example.ex_oauth_jwt.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * packageName    : com.example.ex_oauth_jwt.model
 * fileName       : Role
 * author         : yyh77
 * date           : 2023-08-14
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-08-14        yyh77       최초 생성
 */
@Getter
@RequiredArgsConstructor
public enum Role {

    GUEST("GUEST"), USER("USER");

    private final String role;
}
