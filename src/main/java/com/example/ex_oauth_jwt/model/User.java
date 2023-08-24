package com.example.ex_oauth_jwt.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

/**
 * packageName    : com.example.ex_oauth_jwt.model
 * fileName       : User
 * author         : yyh77
 * date           : 2023-08-14
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-08-14        yyh77       최초 생성
 */
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    private String email;

    private String nickname;

    @Enumerated(EnumType.STRING)
    private Role role;

    private String refreshToken;

    public static User of(UserDTO userDTO, String refreshToken) {
        return User.builder()
                .email(userDTO.getEmail())
                .nickname(userDTO.getNickname())
                .role(Role.GUEST)
                .refreshToken(refreshToken)
                .build();
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
