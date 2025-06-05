package com.study.security.service;

import com.study.security.dto.RegisterRequest;
import com.study.security.entity.User;
import com.study.security.enums.UserRole;
import com.study.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * 사용자 서비스
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * 회원가입
     */
    @Transactional
    public User createUser(RegisterRequest request) {
        log.info("회원가입 시도: username={}", request.getUsername());

        // 중복 체크
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("이미 존재하는 사용자명입니다: " + request.getUsername());
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("이미 존재하는 이메일입니다: " + request.getEmail());
        }

        // 사용자 생성
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword())) // 비밀번호 암호화
                .email(request.getEmail())
                .role(UserRole.USER) // 기본 권한
                .enabled(true)
                .build();

        User savedUser = userRepository.save(user);
        log.info("회원가입 완료: id={}, username={}", savedUser.getId(), savedUser.getUsername());

        return savedUser;
    }

    /**
     * 관리자 계정 생성 (초기 데이터용)
     */
    @Transactional
    public User createAdmin(String username, String password, String email) {
        log.info("관리자 계정 생성: username={}", username);

        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("이미 존재하는 사용자명입니다: " + username);
        }

        User admin = User.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .email(email)
                .role(UserRole.ADMIN)
                .enabled(true)
                .build();

        return userRepository.save(admin);
    }

    /**
     * 사용자명으로 사용자 찾기
     */
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * 사용자 ID로 찾기
     */
    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    /**
     * 모든 사용자 조회
     */
    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    /**
     * 활성 사용자만 조회
     */
    public List<User> findActiveUsers() {
        return userRepository.findByEnabledTrue();
    }

    /**
     * 권한별 사용자 조회
     */
    public List<User> findUsersByRole(UserRole role) {
        return userRepository.findByRole(role);
    }

    /**
     * 사용자 활성화/비활성화 토글
     */
    @Transactional
    public User toggleUserEnabled(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다: " + userId));

        user.setEnabled(!user.isEnabled());

        log.info("사용자 상태 변경: id={}, enabled={}", userId, user.isEnabled());
        return userRepository.save(user);
    }

    /**
     * 사용자 권한 변경 (관리자만 가능)
     */
    @Transactional
    public User changeUserRole(Long userId, UserRole newRole) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다: " + userId));

        UserRole oldRole = user.getRole();
        user.setRole(newRole);

        log.info("사용자 권한 변경: id={}, {} -> {}", userId, oldRole, newRole);
        return userRepository.save(user);
    }

    /**
     * 비밀번호 변경
     */
    @Transactional
    public void changePassword(Long userId, String newPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다: " + userId));

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        log.info("비밀번호 변경 완료: userId={}", userId);
    }

    /**
     * 사용자명 중복 체크
     */
    public boolean isUsernameExists(String username) {
        return userRepository.existsByUsername(username);
    }

    /**
     * 이메일 중복 체크
     */
    public boolean isEmailExists(String email) {
        return userRepository.existsByEmail(email);
    }

    /**
     * 로그인 검증 (비밀번호 확인)
     */
    public boolean validatePassword(User user, String rawPassword) {
        return passwordEncoder.matches(rawPassword, user.getPassword());
    }

    /**
     * 사용자 삭제 (실제로는 비활성화)
     */
    @Transactional
    public void deleteUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다: " + userId));

        user.setEnabled(false); // 실제 삭제 대신 비활성화
        userRepository.save(user);

        log.info("사용자 비활성화: id={}, username={}", userId, user.getUsername());
    }
}