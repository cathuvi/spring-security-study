package com.study.security.jwt;

import com.study.security.service.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.IOException;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * 디버깅용 JWT 필터 테스트 🔍
 *
 * 각 단계별로 상세한 로그와 설명을 포함한 테스트
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("디버깅용 JWT Filter 테스트")
class DebugJwtFilterTest {

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private CustomUserDetailsService customUserDetailsService;

    @Mock
    private FilterChain filterChain;

    private JwtAuthenticationFilter jwtAuthenticationFilter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        System.out.println("\n🔧 === 테스트 준비 단계 ===");

        jwtAuthenticationFilter = new JwtAuthenticationFilter(
                jwtTokenProvider,
                customUserDetailsService
        );

        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();

        SecurityContextHolder.clearContext();

        System.out.println("✅ JwtAuthenticationFilter 생성 완료");
        System.out.println("✅ MockHttpServletRequest 생성 완료");
        System.out.println("✅ SecurityContext 초기화 완료");
    }

    @Test
    @DisplayName("🎯 유효한 토큰 인증 과정 상세 추적")
    void traceValidTokenAuthentication() throws ServletException, IOException {
        System.out.println("\n🎯 === 유효한 토큰 인증 테스트 시작 ===");

        // Given - 테스트 데이터 준비
        String token = "valid.jwt.token";
        String username = "testuser";

        System.out.println("📝 준비된 데이터:");
        System.out.println("   - 토큰: " + token);
        System.out.println("   - 사용자명: " + username);

        // Mock 동작 설정
        System.out.println("\n🤖 Mock 객체 동작 설정:");


        when(jwtTokenProvider.validateToken(token)).thenReturn(true);
        System.out.println("   ✅ validateToken(\"" + token + "\") → true 설정");

        when(jwtTokenProvider.getUsernameFromToken(token)).thenReturn(username);
        System.out.println("   ✅ getUsernameFromToken(\"" + token + "\") → \"" + username + "\" 설정");

        UserDetails mockUser = org.springframework.security.core.userdetails.User.builder()
                .username(username)
                .password("password")
                .authorities(Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")))
                .build();

        when(customUserDetailsService.loadUserByUsername(username)).thenReturn(mockUser);
        System.out.println("   ✅ loadUserByUsername(\"" + username + "\") → mockUser 설정");

        // HTTP 요청 헤더 설정
        request.addHeader("Authorization", "Bearer " + token);
        System.out.println("\n📡 HTTP 요청 헤더 설정:");
        System.out.println("   - Authorization: Bearer " + token);

        // 실행 전 상태 확인
        System.out.println("\n📊 실행 전 상태:");
        System.out.println("   - SecurityContext 인증 정보: " + SecurityContextHolder.getContext().getAuthentication());

        // When - 필터 실행
        System.out.println("\n🚀 === JWT 필터 실행 ===");
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);
        System.out.println("✅ doFilterInternal() 실행 완료");

        // 실행 후 상태 확인
        System.out.println("\n📊 실행 후 상태:");
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            System.out.println("   ✅ SecurityContext에 인증 정보 존재:");
            System.out.println("      - 사용자명: " + auth.getName());
            System.out.println("      - 권한: " + auth.getAuthorities());
            System.out.println("      - 인증 여부: " + auth.isAuthenticated());
        } else {
            System.out.println("   ❌ SecurityContext에 인증 정보 없음");
        }

        // Then - 검증
        System.out.println("\n🔍 === 검증 단계 ===");

        // 1. SecurityContext 검증
        assertThat(auth).isNotNull();
        System.out.println("   ✅ SecurityContext에 인증 정보 존재 확인");

        assertThat(auth.getName()).isEqualTo(username);
        System.out.println("   ✅ 사용자명 일치 확인: " + auth.getName());

        // 2. Mock 호출 횟수 검증
        System.out.println("\n🔍 Mock 메서드 호출 검증:");

        verify(jwtTokenProvider, times(1)).validateToken(token);
        System.out.println("   ✅ validateToken() 1회 호출 확인");

        verify(jwtTokenProvider, times(1)).getUsernameFromToken(token);
        System.out.println("   ✅ getUsernameFromToken() 1회 호출 확인");

        verify(customUserDetailsService, times(1)).loadUserByUsername(username);
        System.out.println("   ✅ loadUserByUsername() 1회 호출 확인");

        verify(filterChain, times(1)).doFilter(request, response);
        System.out.println("   ✅ 다음 필터로 진행 확인");

        System.out.println("\n🎉 === 테스트 성공! ===");
    }

    @Test
    @DisplayName("🚫 토큰 없는 요청 처리 추적")
    void traceRequestWithoutToken() throws ServletException, IOException {
        System.out.println("\n🚫 === 토큰 없는 요청 테스트 시작 ===");

        // Given
        System.out.println("📝 준비: Authorization 헤더 없음");

        // 실행 전 상태
        System.out.println("\n📊 실행 전 상태:");
        System.out.println("   - SecurityContext: " + SecurityContextHolder.getContext().getAuthentication());
        System.out.println("   - 요청 헤더: " + (request.getHeader("Authorization") != null ?
                request.getHeader("Authorization") : "없음"));

        // When
        System.out.println("\n🚀 === JWT 필터 실행 ===");
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);
        System.out.println("✅ doFilterInternal() 실행 완료");

        // 실행 후 상태
        System.out.println("\n📊 실행 후 상태:");
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("   - SecurityContext: " + (auth != null ? auth.getName() : "인증 정보 없음"));

        // Then
        System.out.println("\n🔍 === 검증 단계 ===");

        assertThat(auth).isNull();
        System.out.println("   ✅ SecurityContext 비어있음 확인");

        // Mock 호출 안 됨 확인
        verify(jwtTokenProvider, never()).validateToken(anyString());
        System.out.println("   ✅ validateToken() 호출 안됨 확인");

        verify(jwtTokenProvider, never()).getUsernameFromToken(anyString());
        System.out.println("   ✅ getUsernameFromToken() 호출 안됨 확인");

        verify(customUserDetailsService, never()).loadUserByUsername(anyString());
        System.out.println("   ✅ loadUserByUsername() 호출 안됨 확인");

        verify(filterChain, times(1)).doFilter(request, response);
        System.out.println("   ✅ 다음 필터로 진행 확인");

        System.out.println("\n🎉 === 테스트 성공! ===");
    }

    @Test
    @DisplayName("🔍 Mock vs Real 동작 비교 설명")
    void explainMockVsReal() {
        System.out.println("\n🔍 === Mock vs Real 동작 비교 ===");

        System.out.println("\n🤖 Mock 객체 동작:");
        System.out.println("   - jwtTokenProvider.validateToken() → 실제 JWT 검증 안함");
        System.out.println("   - 그냥 when().thenReturn()으로 설정한 값만 반환");
        System.out.println("   - 로그도 안 찍힘 (실제 메서드 실행 안 됨)");

        System.out.println("\n⚡ Real 객체 동작:");
        System.out.println("   - jwtTokenProvider.validateToken() → 실제 JWT 라이브러리 사용");
        System.out.println("   - 실제 암호화 검증, 만료시간 체크 등 실행");
        System.out.println("   - 로그도 찍힘 (실제 메서드 실행됨)");

        System.out.println("\n💡 Mock을 사용하는 이유:");
        System.out.println("   - 빠른 테스트 (외부 의존성 제거)");
        System.out.println("   - 정확한 행위 검증 (몇 번 호출되었는지 확인)");
        System.out.println("   - 예외 상황 시뮬레이션 (DB 오류 등)");

        System.out.println("\n🎯 이 테스트의 목적:");
        System.out.println("   - JWT 필터의 로직이 올바른 순서로 실행되는가?");
        System.out.println("   - 각 상황에서 적절한 메서드가 호출되는가?");
        System.out.println("   - SecurityContext에 올바르게 저장되는가?");
    }
}