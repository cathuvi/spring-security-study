package com.study.security.jwt;

import com.study.security.service.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT 토큰 검증 경비원 🛡️
 *
 * 아파트 입구에서 출입증(JWT 토큰)을 확인하는 경비원
 * - 출입증이 있는지 확인
 * - 출입증이 진짜인지 검증
 * - 출입증 주인이 누구인지 파악
 * - 주민 등록부(SecurityContext)에 기록
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        try {
            // 1️⃣ 출입증(JWT 토큰) 확인
            String jwt = getJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && jwtTokenProvider.validateToken(jwt)) {
                // 2️⃣ 출입증에서 이름 읽기
                String username = jwtTokenProvider.getUsernameFromToken(jwt);

                // 3️⃣ 주민 정보 조회 (DB에서 사용자 정보 가져오기)
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

                // 4️⃣ 인증 토큰 생성 (주민증 만들기)
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,           // 주인 정보
                                null,                  // 비밀번호는 이미 확인했으니 null
                                userDetails.getAuthorities()  // 권한 목록
                        );

                // 5️⃣ 요청 정보 추가 (어디서 왔는지 기록)
                authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // 6️⃣ 주민 등록부에 기록 (SecurityContext에 저장)
                SecurityContextHolder.getContext().setAuthentication(authentication);

                log.debug("JWT 인증 성공: 사용자={}, 권한={}",
                        username, userDetails.getAuthorities());
            }

        } catch (Exception ex) {
            log.error("JWT 인증 처리 중 오류 발생", ex);
            // 오류가 발생해도 필터 체인은 계속 진행
            // SecurityContext에 인증 정보가 없으면 자동으로 익명 사용자 처리됨
        }

        // 7️⃣ 다음 경비원에게 넘기기 (다음 필터로 진행)
        filterChain.doFilter(request, response);
    }

    /**
     * 🔍 HTTP 요청에서 JWT 토큰 추출하기
     *
     * Authorization 헤더에서 "Bearer " 접두사를 제거하고 토큰만 추출
     * 예: "Bearer eyJ0eXAi..." → "eyJ0eXAi..."
     */
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            String token = bearerToken.substring(7); // "Bearer " 제거 (7글자)
            log.debug("JWT 토큰 추출 성공: {}...", token.substring(0, Math.min(20, token.length())));
            return token;
        }

        log.debug("JWT 토큰 없음: Authorization 헤더가 없거나 Bearer로 시작하지 않음");
        return null;
    }

    /**
     * 🚫 이 필터를 건너뛸 요청들 정의
     *
     * 로그인, 회원가입 등은 토큰이 없어도 되니까 건너뛰기
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();

        // 인증이 필요 없는 경로들
        return path.equals("/api/auth/login") ||        // 로그인만
                path.equals("/api/auth/register") ||     // 회원가입만
                path.equals("/api/auth/refresh") ||      // 토큰 갱신만
                path.startsWith("/api/auth/check-") ||   // 중복 체크만
                path.startsWith("/api/public/") ||       // 공개 API
                path.startsWith("/h2-console/") ||       // H2 콘솔
                path.equals("/") ||                      // 루트
                path.startsWith("/static/");             // 정적 리소스

    }
}