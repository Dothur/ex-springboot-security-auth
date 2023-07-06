package com.example.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Slf4j
@Controller // 로그인 페이지를 보여주기 위해
@RequestMapping("/users")
public class UserController {

    // 1. login 페이지로 온다.
    // 2. login 페이지에 아이디 비밀번호를 입력한다.
    // 3. 성공 하면 my-profile 로 이동한다.

    // 로그인 페이지를 위한 GetMapping
    @GetMapping("/login")
    public String loginForm() {
        return "login-form";
    }

    // 로그인 성공 후 로그인 여부를 판단하기 위한 GetMapping
    @GetMapping("/my-profile")
    public String myProfile(
            Authentication authentication
    ) {
        log.info(authentication.getName());
        log.info(((User) authentication.getPrincipal()).getUsername());
        log.info(SecurityContextHolder.getContext().getAuthentication().getName());
        return "my-profile";
    }

    // 1. 사용자가 register 페이지로 온다.
    // 2. 사용자가 register 페이지에 ID, 비밀번호, 비밀번호 확인을 입력
    // 3. register 페이지 에서 /users/register 로 POST 요청
    // 4. UserDetailsManager 에 새로운 사용자 정보 추가
    @GetMapping("/register")
    public String registerForm() {
        return "register-form";
    }

    // 어떻게 사용자를 관리하는지는 상관 없음
    // interface 기반으로 의존성 주입
    private final UserDetailsManager manager;
    private final PasswordEncoder passwordEncoder;

    public UserController(UserDetailsManager manager, PasswordEncoder passwordEncoder) {
        this.manager = manager;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public String registerPost(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            @RequestParam("password-check") String passwordCheck
    ) {
        // 사용자가 입력한 아이디 비밀번호 비밀번호 확인 값을 확인해 보세요.
        log.info(username);
        log.info(password);
        log.info(passwordCheck);

        if (password.equals(passwordCheck)) {
            log.info("password match !!");

            manager.createUser(
                    User.withUsername(username)
                            .password(passwordEncoder.encode(password))
                            .build()
            );
            return "redirect:/users/login";
            // username 중복도 확인 해야하지만, 이 부분은 service 에서 진행하는 것도 나쁘지않음
        }
        log.warn("password does not match...");
        return "redirect:/users/register?error";
    }
}