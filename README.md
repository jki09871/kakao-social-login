# Kakao Social Login

## 개요

이 프로젝트는 Spring Boot를 사용하여 카카오 로그인 기능을 구현한 소셜 로그인 애플리케이션입니다.
사용자 인증은 JWT(Json Web Token)를 사용하며, 사용자 정보는 MySQL 데이터베이스에 저장됩니다.
로그인된 사용자 정보는 JWT 토큰으로 보호되며, 인증된 사용자는 자신의 정보에 접근할 수 있습니다.

## 주요 기능

- 카카오 소셜 로그인
- JWT 토큰을 이용한 인증
- 사용자 권한 관리 (`USER`, `ADMIN`)
- BCrypt를 사용한 비밀번호 암호화
- MySQL 데이터베이스와의 연동
- 사용자 정보 표시 및 인증

## 기술 스택

- **Java 17**
- **Spring Boot 3.x**
- **Spring Data JPA**
- **Spring Security (JWT)**
- **Thymeleaf**
- **MySQL**
- **BCrypt**
- **Lombok**
- **JSON Web Token (JWT)**
- **jQuery**

## 프로젝트 설정

### 1. git

````
$ git clone https://github.com/jki09871/kakao-social-login.git
````

### 2. MySQL 설정

MySQL을 사용하기 위해 application.properties 파일에서 데이터베이스 연결 정보를 설정
아래 설정을 프로젝트의 src/main/resources/application.properties 파일에 추가

````
spring.datasource.url=jdbc:mysql://localhost:3306/your_db_name
spring.datasource.username=your_username
spring.datasource.password=your_password
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
````

### 3. JWT 시크릿 키 설정

JWT 토큰을 생성할 때 사용할 시크릿 키를 application.properties에 추가

```
jwt.secret.key=your_secret_key
your_secret_key는 암호화에 사용될 비밀키로, 외부에 노출되지 않도록 관리
```

### 4. Gradle 의존성 설정

프로젝트의 build.gradle 파일에 다음과 같은 의존성(dependencies)을 추가

```
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.boot:spring-boot-starter-web'
    compileOnly 'org.projectlombok:lombok'
    runtimeOnly 'com.mysql:mysql-connector-j'
    annotationProcessor 'org.projectlombok:lombok'
    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
    implementation 'at.favre.lib:bcrypt:0.10.2'

    implementation 'org.springframework.boot:spring-boot-starter-thymeleaf'
    
    // JWT
    compileOnly group: 'io.jsonwebtoken', name: 'jjwt-api', version: '0.11.5'
    runtimeOnly group: 'io.jsonwebtoken', name: 'jjwt-impl', version: '0.11.5'
    runtimeOnly group: 'io.jsonwebtoken', name: 'jjwt-jackson', version: '0.11.5'

    // JSON
    implementation 'org.json:json:20230227'
}

```

## API 설명

### 1. 카카오 로그인 콜백

URL: /api/user/kakao/callback
Method: GET
Description: 카카오 인증 서버에서 받은 인가 코드를 통해 JWT 토큰을 생성하고, 이를 쿠키에 저장한 후 리다이렉트.

````
@GetMapping("/user/kakao/callback")
public String kakaoLogin(@RequestParam String code, HttpServletResponse response) throws JsonProcessingException {
    String createToken = kakaoLoginService.kakaoLogin(code, response);

    Cookie cookie = new Cookie(JwtUtil.AUTHORIZATION_HEADER, createToken.substring(7));
    cookie.setPath("/");
    response.addCookie(cookie);

    return "redirect:/api/success";
}
````

### 2. 사용자 정보 조회

URL: /api/user-info
Method: GET
Description: JWT 토큰을 통해 인증된 사용자 정보를 반환합니다.

```
@GetMapping("/user-info")
@ResponseBody
public UserInfoDto getUserInfo(@RequestParam String auth) {
    UserInfoDto userInfo = kakaoLoginService.getUserInfo(auth);
    return userInfo;
}
```

### JWT 토큰 생성

다음 코드는 JWT 토큰을 생성하는 코드입니다. 여기에는 사용자 이름, 이메일, 권한이 포함됩니다.

```
public String createToken(String username, String email, UserRoleEnum role) {
Date date = new Date();

return BEARER_PREFIX +
        Jwts.builder()
                .setSubject(username) // 사용자 이름
                .claim("email", email) // 사용자 이메일 추가
                .claim(AUTHORIZATION_KEY, role) // 사용자 권한
                .setExpiration(new Date(date.getTime() + TOKEN_TIME)) // 만료 시간
                .setIssuedAt(date) // 발급 시간
                .signWith(key, signatureAlgorithm) // 서명 알고리즘
                .compact();
}
```
# 사용자 인터페이스 (HTML & jQuery)
사용자 정보를 화면에 표시하기 위해 다음과 같은 HTML 및 jQuery 코드를 사용할 수 있습니다.
````
<!DOCTYPE html>
<html lang="en">
<head>
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/js-cookie/3.0.1/js.cookie.min.js"></script>
    <meta charset="UTF-8">
    <title>User Info</title>
</head>
<body>
<div id="header-title-login-user">
    이름: <span id="username"></span></br>
    등급: <span id="userRole"></span>
</div>
</body>
</html>

<script>
    $(document).ready(function () {
        const auth = getToken();

        $.ajax({
            type: 'GET',
            url: "/api/user-info",
            contentType: 'application/json',
            data: { auth: auth }
        }).done(function (res) {
            const username = res.username;
            const userRole = res.role;
            if (username) {
                $('#username').text(username);
                $('#userRole').text(userRole);
            } else {
                window.location.href = '/api/user/login-page';
            }
        }).fail(function (jqXHR) {
            if (jqXHR.status === 401 || jqXHR.status === 403) {
                logout();
            } else {
                alert('일시적인 오류가 발생했습니다. 잠시 후 다시 시도해주세요.');
            }
        });

        function getToken() {
            let auth = Cookies.get('Authorization');
            if (auth === undefined) {
                return '';
            }
            if (auth.indexOf('Bearer') === -1 && auth !== '') {
                auth = 'Bearer ' + auth;
            }
            return auth;
        }
    });
</script>
````
