package com.kakao.social.login.entity;

public enum UserRoleEnum {
    USER(Authority.USER),  // 사용자 권한 설정 (USER)
    ADMIN(Authority.ADMIN);  // 관리자 권한 설정 (ADMIN)

    private final String authority; // 각 열거형에 매핑된 권한 값 저장

    // 생성자: 열거형이 생성될 때 권한 값 설정
    UserRoleEnum(String authority) {
        this.authority = authority;
    }

    // 권한 값을 반환하는 getter 메소드
    public String getAuthority() {
        return this.authority;
    }

    // 권한 상수를 포함한 정적 클래스
    public static class Authority {
        // USER 권한의 상수 값 설정 ("ROLE_USER")
        public static final String USER = "ROLE_USER";
        // ADMIN 권한의 상수 값 설정 ("ROLE_ADMIN")
        public static final String ADMIN = "ROLE_ADMIN";
    }
}
