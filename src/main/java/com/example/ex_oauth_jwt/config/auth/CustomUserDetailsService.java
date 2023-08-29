package com.example.ex_oauth_jwt.config.auth;

import com.example.ex_oauth_jwt.model.User;
import com.example.ex_oauth_jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * packageName    : com.example.ex_oauth_jwt.config.auth
 * fileName       : AuthService
 * author         : yyh77
 * date           : 2023-08-28
 * description    : login 요청 시 실행
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023-08-28        yyh77       최초 생성
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    
    private final UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        Optional<User> user = userRepository.findByEmail(email);

        if (!user.isPresent()) {
            throw new RuntimeException("가입되지 않은 사용자입니다.");
        }

        return new CustomUserDetails(user.get());
    }
}
