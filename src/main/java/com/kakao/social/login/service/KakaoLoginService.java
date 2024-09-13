package com.kakao.social.login.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kakao.social.login.config.PasswordEncoder;
import com.kakao.social.login.dto.KakaoUserInfoDto;
import com.kakao.social.login.dto.UserInfoDto;
import com.kakao.social.login.entity.User;
import com.kakao.social.login.entity.UserRoleEnum;
import com.kakao.social.login.jwt.JwtUtil;
import com.kakao.social.login.repository.KakaoLoginRepository;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.UUID;

@Log4j2 // Log4j2 라이브러리를 사용하여 로깅 기능을 제공함을 나타냄
@Service // 해당 클래스를 Spring의 서비스 레이어 컴포넌트로 지정
@RequiredArgsConstructor // final 필드를 포함한 생성자를 자동으로 생성하는 Lombok 어노테이션

public class KakaoLoginService {

    private final KakaoLoginRepository userRepository; // KakaoLoginRepository를 통해 DB 접근
    private final RestTemplate restTemplate; // 외부 API 호출을 위한 RestTemplate 객체
    private final PasswordEncoder passwordEncoder; // 비밀번호 인코딩을 위한 PasswordEncoder 객체
    private final JwtUtil jwtUtil; // JWT 토큰 관련 작업을 위한 유틸리티 클래스

    public String kakaoLogin(String code, HttpServletResponse response) throws JsonProcessingException {
        // 1. "인가 코드"로 "액세스 토큰" 요청
        String accessToken = getToken(code); // 카카오 API로부터 액세스 토큰을 받아옴

        // 2. 토큰으로 카카오 API 호출 : "액세스 토큰"으로 "카카오 사용자 정보" 가져오기
        KakaoUserInfoDto kakaoUserInfo = getKakaoUserInfo(accessToken); // 액세스 토큰으로 사용자 정보 요청

        // 3. 필요시 회원가입
        User kakaoUser = registerKakaoUserIfNeeded(kakaoUserInfo); // 사용자가 없을 경우 회원가입 처리

        // 4. JWT 토큰 반환
        String createToken = jwtUtil.createToken(kakaoUser.getUsername(), kakaoUser.getRole(), kakaoUser.getEmail()); // 사용자 정보로 JWT 생성

        return createToken; // 생성된 JWT 토큰 반환
    }

    private String getToken(String code) throws JsonProcessingException {
        // 요청 URL 만들기
        URI uri = UriComponentsBuilder.fromUriString("https://kauth.kakao.com").path("/oauth/token").encode().build().toUri();
        // 카카오 API 토큰 요청을 위한 URI 생성

        // HTTP Header 생성
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");
        // 요청의 Content-Type을 지정

        // HTTP Body 생성
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code"); // 인증 방식 설정
        body.add("client_id", "f9e131b799a0fab1a582e9b668ac24b5"); // 애플리케이션의 REST API 키
        body.add("redirect_uri", "http://localhost:8080/api/user/kakao/callback"); // 인증 후 리다이렉트될 URI
        body.add("code", code); // 카카오 인증 서버에서 받은 코드

        RequestEntity<MultiValueMap<String, String>> requestEntity = RequestEntity.post(uri).headers(headers).body(body);
        // HTTP 요청을 위한 RequestEntity 생성

        // HTTP 요청 보내기
        ResponseEntity<String> response = restTemplate.exchange(requestEntity, String.class);
        // 카카오 API에 HTTP 요청을 보내고 응답을 받음

        // HTTP 응답 (JSON) -> 액세스 토큰 파싱
        JsonNode jsonNode = new ObjectMapper().readTree(response.getBody());
        // 응답을 JSON 형태로 파싱
        return jsonNode.get("access_token").asText();
        // 액세스 토큰을 추출하여 반환
    }

    private User registerKakaoUserIfNeeded(KakaoUserInfoDto kakaoUserInfo) {
        // DB 에 중복된 Kakao Id 가 있는지 확인
        Long kakaoId = kakaoUserInfo.getId(); // 카카오 사용자 ID 추출
        User kakaoUser = userRepository.findByKakaoId(kakaoId).orElse(null);
        // 카카오 ID로 사용자 정보가 이미 있는지 확인

        if (kakaoUser == null) {
            // 카카오 사용자 email 동일한 email 가진 회원이 있는지 확인
            String kakaoEmail = kakaoUserInfo.getEmail(); // 카카오 사용자 이메일 추출
            User sameEmailUser = userRepository.findByEmail(kakaoEmail).orElse(null);
            // 같은 이메일을 가진 사용자가 DB에 있는지 확인

            if (sameEmailUser != null) {
                kakaoUser = sameEmailUser; // 이메일로 등록된 기존 사용자라면
                // 기존 회원정보에 카카오 Id 추가
                kakaoUser = kakaoUser.kakaoIdUpdate(kakaoId); // 카카오 ID를 업데이트함
            } else {
                // 신규 회원가입
                // password: random UUID
                String password = UUID.randomUUID().toString(); // 비밀번호를 UUID로 생성
                String encodedPassword = passwordEncoder.encode(password); // 비밀번호를 인코딩

                // email: kakao email
                String email = kakaoUserInfo.getEmail(); // 카카오 사용자 이메일 추출
                kakaoUser = User.createUser(kakaoUserInfo.getNickname(), email, encodedPassword, kakaoId, UserRoleEnum.USER);
                // 새로운 사용자 객체를 생성
            }

            userRepository.save(kakaoUser); // 신규 사용자 또는 업데이트된 사용자 정보를 DB에 저장
        }
        return kakaoUser; // 사용자 객체 반환
    }

    private KakaoUserInfoDto getKakaoUserInfo(String accessToken) throws JsonProcessingException {

        // 요청 URL 만들기
        URI uri = UriComponentsBuilder.fromUriString("https://kapi.kakao.com").path("/v2/user/me").encode().build().toUri();
        // 카카오 사용자 정보 요청을 위한 URI 생성

        // HTTP Header 생성
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + accessToken); // 액세스 토큰을 Authorization 헤더에 추가
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");
        // 요청의 Content-Type을 지정

        RequestEntity<MultiValueMap<String, String>> requestEntity = RequestEntity.post(uri).headers(headers).body(new LinkedMultiValueMap<>());
        // HTTP 요청을 위한 RequestEntity 생성

        // HTTP 요청 보내기
        ResponseEntity<String> response = restTemplate.exchange(requestEntity, String.class);
        // 카카오 API에 HTTP 요청을 보내고 응답을 받음

        JsonNode jsonNode = new ObjectMapper().readTree(response.getBody());
        // 응답을 JSON 형태로 파싱
        Long id = jsonNode.get("id").asLong(); // 사용자 ID 추출
        String username = jsonNode.get("properties").get("nickname").asText(); // 사용자 닉네임 추출
        String email = jsonNode.get("kakao_account").get("email").asText(); // 사용자 이메일 추출

        log.info("카카오 사용자 정보: " + id + ", " + username + ", " + email);
        // 사용자 정보를 로그로 출력
        return new KakaoUserInfoDto(id, username, email); // 사용자 정보를 담은 DTO 반환
    }

    public UserInfoDto getUserInfo(String auth) {
        // JWT에서 Bearer 접두사 제거
        String token = auth.substring(7); // Authorization 헤더에서 Bearer 부분을 제외한 JWT 토큰 추출

        jwtUtil.validateToken(token); // 토큰의 유효성을 검사

        // 토큰에서 사용자 정보 추출
        Claims claims = jwtUtil.getUserInfoFromToken(token); // JWT에서 클레임(사용자 정보) 추출

        // 클레임에서 사용자 이름과 권한을 추출
        String username = claims.getSubject(); // 클레임에서 사용자 이름을 추출
        String role = claims.get(JwtUtil.AUTHORIZATION_KEY, String.class); // 클레임에서 사용자 권한을 추출
        String email = claims.get("email", String.class); // 클레임에서 이메일을 추출

        // 사용자 정보 DTO 생성
        return new UserInfoDto(username, role, email); // 사용자 이름과 권한을 포함한 DTO 반환
    }
}
