package com.study.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

/**
 * JWT 토큰 담당 경비원 🔐
 * - 토큰 만들기 (출입증 발급)
 * - 토큰 확인하기 (출입증 검증)
 * - 토큰에서 정보 뽑기 (출입증에서 이름 읽기)
 */
@Component
@Slf4j
public class JwtTokenProvider {

    private final SecretKey secretKey;
    private final long jwtExpiration;

    public JwtTokenProvider(
            @Value("${jwt.secret}") String jwtSecret,
            @Value("${jwt.expiration}") long jwtExpiration) {

        // 비밀 열쇠 만들기 (출입증 위조 방지용)
        this.secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        this.jwtExpiration = jwtExpiration;

        log.info("JWT TokenProvider 초기화 완료! 유효기간: {}ms", jwtExpiration);
    }

    /**
     * 🎫 JWT 토큰 만들기 (출입증 발급)
     * @param authentication 로그인한 사용자 정보
     * @return JWT 토큰 문자열
     */
    public String generateToken(Authentication authentication) {
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();
        Date expiryDate = new Date(System.currentTimeMillis() + jwtExpiration);

        String token = Jwts.builder()
                .subject(userPrincipal.getUsername()) // 주인 이름
                .issuedAt(new Date()) // 발급 날짜
                .expiration(expiryDate) // 만료 날짜
                .signWith(secretKey) // 위조 방지 서명
                .compact();

        log.info("JWT 토큰 발급 완료: 사용자={}, 만료시간={}",
                userPrincipal.getUsername(), expiryDate);

        return token;
    }

    /**
     * 🎫 사용자명으로 JWT 토큰 만들기 (간단 버전)
     * @param username 사용자명
     * @return JWT 토큰 문자열
     */
    public String generateTokenFromUsername(String username) {
        Date expiryDate = new Date(System.currentTimeMillis() + jwtExpiration);

        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(expiryDate)
                .signWith(secretKey)
                .compact();
    }

    /**
     * 👀 토큰에서 사용자명 뽑아내기 (출입증에서 이름 읽기)
     * @param token JWT 토큰
     * @return 사용자명
     */
    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getSubject();
    }

    /**
     * ✅ 토큰이 진짜인지 확인하기 (출입증 검증)
     * @param token JWT 토큰
     * @return 유효하면 true, 아니면 false
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token);

            log.debug("JWT 토큰 검증 성공");
            return true;

        } catch (SecurityException | MalformedJwtException e) {
            log.error("잘못된 JWT 서명입니다: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("만료된 JWT 토큰입니다: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("지원되지 않는 JWT 토큰입니다: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT 토큰이 비어있습니다: {}", e.getMessage());
        }

        return false;
    }

    /**
     * ⏰ 토큰 만료시간 확인
     * @param token JWT 토큰
     * @return 만료 날짜
     */
    public Date getExpirationDateFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getExpiration();
    }

    /**
     * 🕐 토큰이 만료됐는지 확인
     * @param token JWT 토큰
     * @return 만료됐으면 true
     */
    public boolean isTokenExpired(String token) {
        Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    /**
     * 🔄 토큰 갱신이 가능한지 확인
     * @param token JWT 토큰
     * @return 갱신 가능하면 true
     */
    public boolean canTokenBeRefreshed(String token) {
        return !isTokenExpired(token);
    }

    /**
     * 🆕 토큰 갱신하기
     * @param token 기존 토큰
     * @return 새로운 토큰
     */
    public String refreshToken(String token) {
        String username = getUsernameFromToken(token);
        return generateTokenFromUsername(username);
    }
}