package com.kakao.social.login.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter // Lombok 어노테이션: 해당 클래스의 모든 필드에 대한 Getter 메서드를 자동 생성
@Entity // JPA 엔티티 클래스임을 선언하여 해당 클래스가 데이터베이스 테이블과 매핑됨을 나타냄
@Table(name = "users") // 데이터베이스에서 해당 엔티티가 매핑될 테이블명을 "users"로 설정
@NoArgsConstructor // Lombok 어노테이션: 파라미터가 없는 기본 생성자를 자동 생성

public class User {

    @Id@GeneratedValue(strategy = GenerationType.IDENTITY)
    // @Id: 해당 필드가 기본 키(primary key)임을 나타냄
    // @GeneratedValue: 기본 키가 자동으로 생성됨을 나타내며, 전략은 IDENTITY(데이터베이스에서 자동 증가하는 ID 사용)
    private Long id;

    @Column(length = 20)
    // username 필드를 데이터베이스 컬럼과 매핑하며, 문자열 최대 길이는 20자로 제한
    private String username;

    @Column(length = 100)
    // email 필드를 데이터베이스 컬럼과 매핑하며, 문자열 최대 길이는 100자로 제한
    private String email;

    @Column(length = 300)
    // password 필드를 데이터베이스 컬럼과 매핑하며, 비밀번호는 최대 300자로 제한 (암호화된 비밀번호 저장을 고려)
    private String password;

    @Column(unique = true)
    // kakaoId 필드를 데이터베이스 컬럼과 매핑하며, 해당 값은 유일해야 함 (카카오 ID는 중복 불가)
    private Long kakaoId;

    @Column(nullable = false)
    // role 필드를 데이터베이스 컬럼과 매핑하며, 값이 반드시 존재해야 함 (NULL 불가)
    @Enumerated(value = EnumType.STRING)
    // role 필드는 EnumType.STRING으로 매핑되어, 열거형의 값을 문자열로 저장함 (UserRoleEnum의 값을 DB에 저장)
    private UserRoleEnum role;

    // User 클래스의 생성자 (파라미터로 받은 값으로 사용자 객체 생성)
    public User(String username, String email,String password, Long kakaoId, UserRoleEnum role) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.kakaoId = kakaoId;
        this.role = role;
    }

    // 정적 팩토리 메소드: 객체 생성을 보다 명확하게 해주는 역할
    public static User createUser(String username, String email, String password, Long kakaoId, UserRoleEnum role) {
        return new User(username, email, password, kakaoId, role);
        // 새로운 User 객체를 생성하여 반환
    }

    // 카카오 ID를 업데이트하는 메소드
    public User kakaoIdUpdate(Long kakaoId) {
        this.kakaoId = kakaoId; // 기존 사용자 객체의 카카오 ID를 업데이트
        return this; // 업데이트된 객체를 반환
    }
}

