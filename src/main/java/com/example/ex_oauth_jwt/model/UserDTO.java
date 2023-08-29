package com.example.ex_oauth_jwt.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * packageName    : com.example.ex_oauth_jwt.model
 * fileName       : UserDTO
 * author         : yyh77
 * date           : 2023-08-14
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-08-14        yyh77       최초 생성
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDTO {

    private String email;

    private String nickname;

    private String password;

    public static UserDTO of(OAuth2User oAuth2User) {
        return UserDTO.builder()
                .email(oAuth2User.getAttribute("email"))
                .password(null)
                .nickname(oAuth2User.getAttribute("nickname"))
                .build();
    }

    public static UserDTO of(User user) {
        return UserDTO.builder()
                .email(user.getEmail())
                .password(user.getPassword())
                .nickname(user.getNickname())
                .build();
    }
}
