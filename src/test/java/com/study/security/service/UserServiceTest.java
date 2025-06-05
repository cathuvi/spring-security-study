package com.study.security.service;

import com.study.security.dto.RegisterRequest;
import com.study.security.entity.User;
import com.study.security.enums.UserRole;
import com.study.security.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static org.assertj.core.api.Assertions.*;


@SpringBootTest
@ActiveProfiles("test")
@Transactional
@DisplayName("UserServiceTest")
class UserServiceTest {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("회원 가입 테스트 성공")
    void createUser() {
        //given
        RegisterRequest request = new RegisterRequest();
        request.setUsername("cafe");
        request.setEmail("cafe@cafe.co.kr");
        request.setPassword("!Cafe2413");

        //when
        User savedUser = userService.createUser(request);

        //then
        assertThat(savedUser).isNotNull();
        assertThat(savedUser.getUsername()).isEqualTo("cafe");
        assertThat(savedUser.getEmail()).isEqualTo("cafe@cafe.co.kr");
        assertThat(savedUser.getRole()).isEqualTo(UserRole.USER);
        assertThat(savedUser.isEnabled()).isTrue();

        assertThat(savedUser.getPassword()).isNotEqualTo("!Cafe2413");

    }

    @Test
    @DisplayName("중복 사용자명으로 회원가입 실패")
    void createUser_DuplicateUsername_Fail(){
        //given
        RegisterRequest request1 = new RegisterRequest();
        request1.setUsername("d1");
        request1.setEmail("d1@cafe.co.kr");
        request1.setPassword("!Cafe2413");

        RegisterRequest request2 = new RegisterRequest();
        request2.setUsername("d1");
        request2.setEmail("d2@cafe.co.kr");
        request2.setPassword("!Cafe2413");

        //when
        userService.createUser(request1);
        //then
        assertThatThrownBy(() -> userService.createUser(request2))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("이미 존재하는 사용자명입니다.");
    }



    @Test
    @DisplayName("사용자 명으로 검색 성공")
    void findByUsername_success() {
        //given
        RegisterRequest request = new RegisterRequest();
        request.setUsername("findUser");
        request.setPassword("cafe2413");
        request.setEmail("findme@example.co.kr");

        User savedUser = userService.createUser(request);
        //when
        Optional<User> foundUser = userService.findByUsername("findUser");

        //then
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getId()).isEqualTo(savedUser.getId());
        assertThat(foundUser.get().getEmail()).isEqualTo("findme@example.co.kr");
    }

    @Test
    @DisplayName("비밀번호 검증 테스트")
    void validatePassword_success() {
        //given
        RegisterRequest request = new RegisterRequest();
        request.setUsername("pwdtest");
        request.setPassword("mypassword");
        request.setEmail("pwd@example.co.kr");

        User savedUser = userService.createUser(request);
        //when  //then
        assertThat(userService.validatePassword(savedUser,"mypassword"));

    }

    @Test
    @DisplayName("권한 변경 테스트 성공")
    void findAllUsers() {
        //given
        RegisterRequest request = new RegisterRequest();
        request.setUsername("pwdtest");
        request.setPassword("mypassword");
        request.setEmail("pwd@example.co.kr");

        User savedUser = userService.createUser(request);
        assertThat(savedUser.getRole()).isEqualTo(UserRole.USER);
        //when
        User updateUser = userService.changeUserRole(savedUser.getId(),UserRole.ADMIN);

        //then
        assertThat(updateUser.getRole()).isEqualTo(UserRole.ADMIN);

    }

    @Test
    @DisplayName("사용자 활성화/비활성화 토글")
    void toggleUserEnabled_success() {
        //given
        RegisterRequest request = new RegisterRequest();
        request.setUsername("pwdtest");
        request.setPassword("mypassword");
        request.setEmail("pwd@example.co.kr");

        User savedUser = userService.createUser(request);
        assertThat(savedUser.isEnabled()).isTrue();
        //when
        User updateUser = userService.toggleUserEnabled(savedUser.getId());

        //then
        assertThat(updateUser.isEnabled()).isFalse();


    }
//
//    @Test
//    void findUsersByRole() {
//    }
//
//    @Test
//    void toggleUserEnabled() {
//    }
//
//    @Test
//    void changeUserRole() {
//    }
//
//    @Test
//    void changePassword() {
//    }
//
//    @Test
//    void isUsernameExists() {
//    }
//
//    @Test
//    void isEmailExists() {
//    }
//
//    @Test
//    void validatePassword() {
//    }
//
//    @Test
//    void deleteUser() {
//    }
}