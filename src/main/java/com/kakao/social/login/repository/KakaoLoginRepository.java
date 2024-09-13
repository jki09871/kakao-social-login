package com.kakao.social.login.repository;

import com.kakao.social.login.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface KakaoLoginRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);

    Optional<User> findByKakaoId(Long kakaoId);

}
