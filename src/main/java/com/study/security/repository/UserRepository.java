package com.study.security.repository;

import com.study.security.entity.User;
import com.study.security.enums.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * 사용자 Repository - 간단 버전
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // Spring Security에서 사용할 메서드
    Optional<User> findByUsername(String username);

    // 중복 체크용
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);

    // 권한별 조회
    List<User> findByRole(UserRole role);

    // 활성 사용자 조회
    List<User> findByEnabledTrue();
}