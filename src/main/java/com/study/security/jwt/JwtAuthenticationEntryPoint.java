package com.study.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * JWT 인증 실패 처리기 🚫
 *
 * 아파트 경비원이 "출입 불가!" 라고 말할 때 사용하는 안내문
 * - 토큰이 없을 때
 * - 토큰이 잘못되었을 때
 * - 토큰이 만료되었을 때
 * → 모두 여기서 처리!
 */
@Component
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {

        log.warn("인증되지 않은 요청 발생: URI={}, 메서드={}, 에러={}",
                request.getRequestURI(),
                request.getMethod(),
                authException.getMessage());

        // 1️⃣ HTTP 응답 상태 설정
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        // 2️⃣ 에러 상세 분석
        String errorCode = determineErrorCode(request, authException);
        String errorMessage = determineErrorMessage(errorCode, authException);

        // 3️⃣ JSON 응답 생성
        Map<String, Object> errorResponse = createErrorResponse(
                errorCode,
                errorMessage,
                request.getRequestURI()
        );

        // 4️⃣ 응답 전송
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));

        log.debug("401 Unauthorized 응답 전송 완료");
    }

    /**
     * 🔍 에러 코드 결정
     */
    private String determineErrorCode(HttpServletRequest request, AuthenticationException authException) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null) {
            return "MISSING_TOKEN";
        } else if (!authHeader.startsWith("Bearer ")) {
            return "INVALID_TOKEN_FORMAT";
        } else if (authException.getMessage() != null && authException.getMessage().contains("expired")) {
            return "EXPIRED_TOKEN";
        } else if (authException.getMessage() != null && authException.getMessage().contains("malformed")) {
            return "MALFORMED_TOKEN";
        } else {
            return "INVALID_TOKEN";
        }
    }

    /**
     * 💬 사용자 친화적인 에러 메시지 생성
     */
    private String determineErrorMessage(String errorCode, AuthenticationException authException) {
        return switch (errorCode) {
            case "MISSING_TOKEN" -> "인증 토큰이 없습니다. Authorization 헤더에 Bearer 토큰을 포함해주세요.";
            case "INVALID_TOKEN_FORMAT" -> "토큰 형식이 올바르지 않습니다. 'Bearer {token}' 형식으로 전송해주세요.";
            case "EXPIRED_TOKEN" -> "토큰이 만료되었습니다. 새로운 토큰으로 다시 로그인해주세요.";
            case "MALFORMED_TOKEN" -> "토큰이 손상되었습니다. 올바른 토큰을 사용해주세요.";
            case "INVALID_TOKEN" -> "유효하지 않은 토큰입니다. 다시 로그인해주세요.";
            default -> "인증에 실패했습니다. 다시 로그인해주세요.";
        };
    }

    /**
     * 📋 JSON 에러 응답 생성
     */
    private Map<String, Object> createErrorResponse(String errorCode, String errorMessage, String path) {
        Map<String, Object> errorResponse = new HashMap<>();

        // 기본 에러 정보
        errorResponse.put("success", false);
        errorResponse.put("error", "UNAUTHORIZED");
        errorResponse.put("errorCode", errorCode);
        errorResponse.put("message", errorMessage);

        // 요청 정보
        errorResponse.put("path", path);
        errorResponse.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

        // 해결 방법 안내
        errorResponse.put("solution", getSolution(errorCode));

        return errorResponse;
    }

    /**
     * 💡 해결 방법 안내
     */
    private String getSolution(String errorCode) {
        return switch (errorCode) {
            case "MISSING_TOKEN" -> "POST /api/auth/login 으로 로그인하여 토큰을 발급받으세요.";
            case "INVALID_TOKEN_FORMAT" -> "헤더를 'Authorization: Bearer {your-token}' 형식으로 수정하세요.";
            case "EXPIRED_TOKEN" -> "POST /api/auth/login 으로 다시 로그인하세요.";
            case "MALFORMED_TOKEN", "INVALID_TOKEN" -> "POST /api/auth/login 으로 새로운 토큰을 발급받으세요.";
            default -> "POST /api/auth/login 으로 로그인하세요.";
        };
    }
}