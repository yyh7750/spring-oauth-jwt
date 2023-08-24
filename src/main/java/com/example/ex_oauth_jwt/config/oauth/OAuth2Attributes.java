package com.example.ex_oauth_jwt.config.oauth;

import lombok.*;

import java.util.HashMap;
import java.util.Map;

/**
 * packageName    : com.example.ex_oauth_jwt.config.oauth
 * fileName       : OAuth2Attributes
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
@ToString
public class OAuth2Attributes {

    private Map<String, Object> attributes;
    private String attributeKey;
    private String email;
    private String nickname;

    public static OAuth2Attributes of(String provider, String attributeKey, Map<String, Object> attributes) {

        switch (provider) {
            case "google":
                return ofGoogle(attributeKey, attributes);
            case "kakao":
                return ofKakao(attributeKey, attributes);
            default:
                throw new RuntimeException();
        }
    }

    private static OAuth2Attributes ofKakao(String attributeKey, Map<String, Object> attributes) {

        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> kakaoProfile = (Map<String, Object>) kakaoAccount.get("profile");

        return OAuth2Attributes.builder()
                .email((String) kakaoAccount.get("email"))
                .nickname((String) kakaoProfile.get("nickname"))
                .attributes(kakaoAccount)
                .attributeKey(attributeKey)
                .build();
    }

    private static OAuth2Attributes ofGoogle(String attributeKey, Map<String, Object> attributes) {
        return OAuth2Attributes.builder()
                .email((String) attributes.get("email"))
                .nickname((String) attributes.get("nickname"))
                .attributes(attributes)
                .attributeKey(attributeKey)
                .build();
    }

    public Map<String, Object> convertToMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", attributeKey);
        map.put("key", attributeKey);
        map.put("email", email);
        map.put("nickname", nickname);
        return map;
    }
}
