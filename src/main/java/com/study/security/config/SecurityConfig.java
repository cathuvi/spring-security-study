package com.study.security.config;

import com.study.security.jwt.JwtAuthenticationEntryPoint;
import com.study.security.jwt.JwtAuthenticationFilter;
import com.study.security.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security 설정 🛡️
 *
 * 아파트 보안 시스템 총괄 설정
 * - 출입 통제 규칙
 * - 경비원 배치 (필터들)
 * - 보안 정책 설정
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * 🔐 AuthenticationManager Bean 등록
     *
     * AuthController의 로그인 처리에서 사용
     * 사용자의 아이디/비밀번호를 검증하는 관리자
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * 🔑 PasswordEncoder Bean 등록
     *
     * 비밀번호 암호화/검증 담당
     * BCrypt 알고리즘 사용 (강력한 해시 함수)
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 🛡️ Security Filter Chain 설정
     *
     * 보안 필터들의 동작 규칙 정의
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 1️⃣ CSRF 보호 비활성화 (JWT 사용 시 불필요)
                .csrf(csrf -> csrf.disable())

                // 2️⃣ 세션 관리 정책 (Stateless - 세션 사용 안 함)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 3️⃣ URL별 접근 권한 설정
                .authorizeHttpRequests(auth -> auth
                        // 인증 없이 접근 가능한 경로들
                        .requestMatchers("/api/auth/login").permitAll()       // 로그인
                        .requestMatchers("/api/auth/register").permitAll()    // 회원가입
                        .requestMatchers("/api/auth/refresh").permitAll()     // 토큰 갱신
                        .requestMatchers("/api/auth/check-*").permitAll()     // 중복 체크
                        .requestMatchers("/api/public/**").permitAll()        // 공개 API
                        .requestMatchers("/h2-console/**").permitAll()        // H2 데이터베이스 콘솔
                        .requestMatchers("/", "/favicon.ico").permitAll()     // 기본 페이지

                        // 인증이 필요한 경로들
                        .requestMatchers("/api/auth/status").authenticated()  // 상태 확인은 인증 필요 ⭐️
                        .requestMatchers("/api/auth/logout").authenticated()  // 로그아웃도 인증 필요

                        // 권한별 접근 제어
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")    // 관리자만

                        // 나머지 모든 요청은 인증 필요
                        .anyRequest().authenticated()
                )

                // 4️⃣ 예외 처리 설정
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint) // 인증 실패 시 처리
                )

                // 5️⃣ JWT 필터 추가 (UsernamePasswordAuthenticationFilter 앞에 배치)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}

/**
 * 🎯 Spring Security 6.x 최신 방식 특징:
 *
 * ✅ 자동 설정 활용:
 *   - DaoAuthenticationProvider 수동 설정 불필요
 *   - UserDetailsService + PasswordEncoder Bean만 등록하면 자동 연결
 *   - Spring Boot Auto-Configuration이 나머지 처리
 *
 * ✅ 함수형 설정:
 *   - Lambda 표현식 사용 (.csrf(csrf -> csrf.disable()))
 *   - 더 읽기 쉽고 간결한 코드
 *
 * ✅ 명확한 책임 분리:
 *   - SecurityConfig: 보안 정책 정의
 *   - JwtAuthenticationFilter: JWT 토큰 처리
 *   - JwtAuthenticationEntryPoint: 인증 실패 처리
 *   - CustomUserDetailsService: 사용자 정보 조회
 */