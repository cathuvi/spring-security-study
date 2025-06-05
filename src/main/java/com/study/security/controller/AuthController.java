package com.study.security.controller;

import com.study.security.dto.LoginRequest;
import com.study.security.dto.LoginResponse;
import com.study.security.dto.RegisterRequest;
import com.study.security.entity.User;
import com.study.security.jwt.JwtTokenProvider;
import com.study.security.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 인증 컨트롤러 🔐
 *
 * 아파트 관리사무소 역할
 * - 주민 등록 (회원가입)
 * - 출입증 발급 (로그인)
 * - 출입증 갱신 (토큰 갱신) 등
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;

    private String auth_token;

    /**
     * 🔑 로그인 (출입증 발급)
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            log.info("로그인 시도: username={}", request.getUsername());

            // 1️⃣ 사용자 인증 (아이디/비밀번호 확인)
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 2️⃣ JWT 토큰 생성 (출입증 발급)
            String jwtToken = jwtTokenProvider.generateToken(authentication);
            auth_token = jwtToken;
            // 3️⃣ 사용자 정보 조회
            User user = userService.findByUsername(request.getUsername())
                    .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다"));

            // 4️⃣ 응답 생성
            LoginResponse response = new LoginResponse(jwtToken, user.getUsername(), user.getRole());

            log.info("로그인 성공: username={}, role={}", user.getUsername(), user.getRole());

            return ResponseEntity.ok(response);

        } catch (BadCredentialsException e) {
            log.warn("로그인 실패 - 잘못된 자격 증명: username={}", request.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(createErrorResponse("INVALID_CREDENTIALS", "아이디 또는 비밀번호가 올바르지 않습니다."));

        } catch (AuthenticationException e) {
            log.warn("로그인 실패 - 인증 오류: username={}, error={}", request.getUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(createErrorResponse("AUTHENTICATION_FAILED", "인증에 실패했습니다."));

        } catch (Exception e) {
            log.error("로그인 처리 중 오류 발생: username={}", request.getUsername(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("INTERNAL_ERROR", "서버 내부 오류가 발생했습니다."));
        }
    }

    /**
     * 📝 회원가입 (주민 등록)
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        try {
            log.info("회원가입 시도: username={}, email={}", request.getUsername(), request.getEmail());

            // 1️⃣ 중복 체크 (이미 등록된 주민인지 확인)
            if (userService.isUsernameExists(request.getUsername())) {
                log.warn("회원가입 실패 - 중복된 사용자명: username={}", request.getUsername());
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(createErrorResponse("DUPLICATE_USERNAME", "이미 사용 중인 사용자명입니다."));
            }

            if (userService.isEmailExists(request.getEmail())) {
                log.warn("회원가입 실패 - 중복된 이메일: email={}", request.getEmail());
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(createErrorResponse("DUPLICATE_EMAIL", "이미 사용 중인 이메일입니다."));
            }

            // 2️⃣ 사용자 생성 (주민 등록)
            User newUser = userService.createUser(request);

            // 3️⃣ 성공 응답
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "회원가입이 완료되었습니다.");
            response.put("username", newUser.getUsername());
            response.put("email", newUser.getEmail());

            log.info("회원가입 성공: id={}, username={}", newUser.getId(), newUser.getUsername());

            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (IllegalArgumentException e) {
            log.warn("회원가입 실패 - 잘못된 입력: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(createErrorResponse("INVALID_INPUT", e.getMessage()));

        } catch (Exception e) {
            log.error("회원가입 처리 중 오류 발생: username={}", request.getUsername(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("INTERNAL_ERROR", "서버 내부 오류가 발생했습니다."));
        }
    }

    /**
     * ✅ 로그인 상태 확인
     */
    @GetMapping("/status")
    public ResponseEntity<?> status(Authentication authentication) {
        System.out.println("authentication = " + authentication);
        if (authentication != null && authentication.isAuthenticated()) {
            Map<String, Object> response = new HashMap<>();
            response.put("authenticated", true);
            response.put("username", authentication.getName());
            response.put("authorities", authentication.getAuthorities());

            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.ok(Map.of("authenticated", false));
        }
    }

    /**
     * 🚪 로그아웃 (실제로는 클라이언트에서 토큰 삭제)
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout() {

        // JWT는 Stateless이므로 서버에서 할 일이 없음
        // 클라이언트에서 토큰을 삭제하면 됨

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "로그아웃 되었습니다. 클라이언트에서 토큰을 삭제해주세요.");

        return ResponseEntity.ok(response);
    }

    /**
     * 🔄 토큰 갱신 (선택사항)
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestHeader("Authorization") String authHeader) {
        try {
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);

                // 토큰 유효성 검증
                if (jwtTokenProvider.validateToken(token)) {
                    String username = jwtTokenProvider.getUsernameFromToken(token);

                    // 새 토큰 생성
                    String newToken = jwtTokenProvider.generateTokenFromUsername(username);

                    Map<String, Object> response = new HashMap<>();
                    response.put("success", true);
                    response.put("token", newToken);
                    response.put("message", "토큰이 갱신되었습니다.");

                    return ResponseEntity.ok(response);
                }
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(createErrorResponse("INVALID_TOKEN", "유효하지 않은 토큰입니다."));

        } catch (Exception e) {
            log.error("토큰 갱신 중 오류 발생", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("INTERNAL_ERROR", "토큰 갱신 중 오류가 발생했습니다."));
        }
    }

    /**
     * 🔍 사용자명 중복 체크
     */
    @GetMapping("/check-username")
    public ResponseEntity<?> checkUsername(@RequestParam String username) {
        boolean exists = userService.isUsernameExists(username);

        Map<String, Object> response = new HashMap<>();
        response.put("exists", exists);
        response.put("available", !exists);
        response.put("message", exists ? "이미 사용 중인 사용자명입니다." : "사용 가능한 사용자명입니다.");

        return ResponseEntity.ok(response);
    }

    /**
     * 📧 이메일 중복 체크
     */
    @GetMapping("/check-email")
    public ResponseEntity<?> checkEmail(@RequestParam String email) {
        boolean exists = userService.isEmailExists(email);

        Map<String, Object> response = new HashMap<>();
        response.put("exists", exists);
        response.put("available", !exists);
        response.put("message", exists ? "이미 사용 중인 이메일입니다." : "사용 가능한 이메일입니다.");

        return ResponseEntity.ok(response);
    }

    /**
     * 🚨 에러 응답 생성 헬퍼 메서드
     */
    private Map<String, Object> createErrorResponse(String errorCode, String message) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("success", false);
        errorResponse.put("errorCode", errorCode);
        errorResponse.put("message", message);
        errorResponse.put("timestamp", System.currentTimeMillis());

        return errorResponse;
    }
}