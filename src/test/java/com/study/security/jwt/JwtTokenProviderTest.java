package com.study.security.jwt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
@DisplayName("JWTTest")
class JwtTokenProviderTest {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Test
    @DisplayName("JWT Provider test")
    void create_valid_extract_token(){
        //create
        String token = jwtTokenProvider.generateTokenFromUsername("testuser");
        System.out.println("token = " + token);

        //valid
        boolean isValid = jwtTokenProvider.validateToken(token);
        System.out.println("isValid = " + isValid);

        //extract userName
        String userName = jwtTokenProvider.getUsernameFromToken(token);
        System.out.println("userName = " + userName);
    }

}