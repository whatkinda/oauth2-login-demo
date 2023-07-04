package com.exercise.security1.controller;

import com.exercise.security1.auth.PrincipalDetails;
import com.exercise.security1.domain.User;
import com.exercise.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Slf4j
@RequiredArgsConstructor
@Controller
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    /*
    * OAuth 로그인을 해도 PrincipalDetails
    * 일반 로그인을 해도 PrincipalDetails
    * */
    @GetMapping("/user")
    @ResponseBody
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        return "user";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager() {
        return "manager";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin() {
        return "admin";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {

        String encodedPw = bCryptPasswordEncoder.encode(user.getPassword());
        user.setPassword(encodedPw);
        user.setRole("ROLE_USER");

        userRepository.save(user);

        return "redirect:/loginForm";
    }

    @GetMapping("/test/login")
    @ResponseBody
    public String loginTest(
            Authentication authentication,
            @AuthenticationPrincipal PrincipalDetails userDetails
    ) {
        log.debug("=========== /test/login ===========");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        log.debug("=========== authentication : {}" , principalDetails.getUser());

        log.debug("========userDetails : {}", userDetails.getUser());

        return "세션정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    @ResponseBody
    public String oAuthLoginTest(
            Authentication authentication,
            @AuthenticationPrincipal OAuth2User oauth) {
        log.debug("=========== /test/oauth/login ===========");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        log.debug("=========== oAuth2User.getAttributes() : {}" , oAuth2User.getAttributes());
        log.debug("=========== oauth.getAttributes() : {}", oauth.getAttributes());

        return "oAuth 세션정보 확인하기";
    }
}
