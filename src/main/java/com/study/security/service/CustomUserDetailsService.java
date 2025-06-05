package com.study.security.service;

import com.study.security.entity.User;
import com.study.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

/**
 * 사용자 정보 조회 서비스 👤
 *
 * JWT 토큰에서 사용자명을 읽은 후,
 * 실제 사용자 정보를 데이터베이스에서 조회하는 서비스
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * 🔍 사용자명으로 사용자 정보 조회
     *
     * Spring Security가 호출하는 메서드
     * JWT 필터에서 토큰의 사용자명을 가지고 이 메서드를 호출함
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("사용자 정보 조회 시도: username={}", username);

        // 데이터베이스에서 사용자 찾기
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("사용자를 찾을 수 없음: username={}", username);
                    return new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username);
                });

        // 비활성화된 사용자 체크
        if (!user.isEnabled()) {
            log.warn("비활성화된 사용자: username={}", username);
            throw new UsernameNotFoundException("비활성화된 사용자입니다: " + username);
        }

        log.debug("사용자 정보 조회 성공: username={}, role={}", username, user.getRole());

        // Spring Security의 UserDetails 객체로 변환
        return createUserDetails(user);
    }

    /**
     * 🏷️ User 엔티티를 UserDetails로 변환
     */
    private UserDetails createUserDetails(User user) {
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())  // 이미 암호화된 비밀번호
                .authorities(Collections.singletonList(
                        new SimpleGrantedAuthority(user.getRole().getAuthority())
                ))
                .accountExpired(false)         // 계정 만료 여부
                .accountLocked(false)          // 계정 잠금 여부
                .credentialsExpired(false)     // 비밀번호 만료 여부
                .disabled(!user.isEnabled())   // 계정 비활성화 여부
                .build();
    }

    /**
     * 🆔 사용자 ID로 UserDetails 조회 (추가 메서드)
     */
    public UserDetails loadUserById(Long userId) {
        log.debug("사용자 정보 조회 시도: userId={}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("사용자를 찾을 수 없음: userId={}", userId);
                    return new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + userId);
                });

        return createUserDetails(user);
    }
}