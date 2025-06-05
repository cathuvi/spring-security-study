package com.study.security.entity;

import com.study.security.enums.UserRole;
import jakarta.persistence.*;
import lombok.*;

/**
 * 사용자 Entity - 간단 버전
 */
@Entity
@Table(name = "users")
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(unique = true, nullable = false)
    private String email;

    @Enumerated(EnumType.STRING)
    private UserRole role = UserRole.USER;

    private boolean enabled = true;
}