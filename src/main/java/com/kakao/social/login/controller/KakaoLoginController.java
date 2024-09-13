package com.kakao.social.login.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.kakao.social.login.dto.UserInfoDto;
import com.kakao.social.login.entity.User;
import com.kakao.social.login.jwt.JwtUtil;
import com.kakao.social.login.service.KakaoLoginService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Log4j2
@Controller
@RequiredArgsConstructor
@RequestMapping("/api")
public class KakaoLoginController {

    private final KakaoLoginService kakaoLoginService;

    @GetMapping("/success")
    public String loginSuccess() {
        return "success";
    }

    @GetMapping("/user/kakao/callback")
    public String kakaoLogin(@RequestParam String code, HttpServletResponse response) throws JsonProcessingException {
        String createToken = kakaoLoginService.kakaoLogin(code, response);

        Cookie cookie = new Cookie(JwtUtil.AUTHORIZATION_HEADER, createToken.substring(7));
        cookie.setPath("/");
        response.addCookie(cookie);

        return "redirect:/api/success";
    }

    @GetMapping("/user-info")
    @ResponseBody
    public UserInfoDto getUserInfo(@RequestParam String auth) {

        // JWT 토큰에서 사용자 정보를 추출하고 반환
        UserInfoDto userInfo = kakaoLoginService.getUserInfo(auth);

        return userInfo;
    }
}
