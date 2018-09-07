> 本文是基于上一篇 [Spring Cloud OAuth2 token存数据库实现](https://www.jianshu.com/p/4ce5577bab74) ，改造为oauth2+jwt；
源码地址：https://github.com/liangxiaobo/test-security-oauth2/tree/master-jwt 注意是分支master-jwt

> 什么是JWT
Json web token (JWT), 是为了在网络应用环境间传递声明而执行的一种基于JSON的开放标准（[RFC 7519](https://link.jianshu.com?t=https://tools.ietf.org/html/rfc7519)).该token被设计为紧凑且安全的，特别适用于分布式站点的单点登录（SSO）场景。JWT的声明一般被用来在身份提供者和服务提供者间传递被认证的用户身份信息，以便于从资源服务器获取资源，也可以增加一些额外的其它业务逻辑所必须的声明信息，该token也可直接被用于认证，也可被加密。


## 1. 改造项目service-auth
![v1.png](https://upload-images.jianshu.io/upload_images/2151905-5dbe3b3fca921193.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/850)

因为Spring Cloud OAuth2中包含了Spring Security OAuth2和Spring Security JWT的依赖，所以不用修改pom.xml
### 1.1 修改AuthorizationServerConfiguration
``` java
package com.service.auth.serviceauth.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.sql.DataSource;
import java.util.concurrent.TimeUnit;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    @Qualifier("authenticationManagerBean")
    AuthenticationManager authenticationManager;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private ClientDetailsService clientDetailsService;


    static final Logger logger = LoggerFactory.getLogger(AuthorizationServerConfiguration.class);

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("test-jwt.jks"), "test123".toCharArray());
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setKeyPair(keyStoreKeyFactory.getKeyPair("test-jwt"));
        return converter;
    }

    @Bean // 声明 ClientDetails实现
    public ClientDetailsService clientDetailsService() {
        return new JdbcClientDetailsService(dataSource);
    }


    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientDetailsService);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(tokenStore).tokenEnhancer(jwtAccessTokenConverter()).authenticationManager(authenticationManager);

        // 配置tokenServices参数
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(endpoints.getTokenStore());
        tokenServices.setSupportRefreshToken(false);
        tokenServices.setClientDetailsService(endpoints.getClientDetailsService());
        tokenServices.setTokenEnhancer(endpoints.getTokenEnhancer());
        tokenServices.setAccessTokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(30)); // 30天
        endpoints.tokenServices(tokenServices);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // 允许表单认证
        security.allowFormAuthenticationForClients().tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }
}

```
### 1.2 test-jwt
代码中的test-jwt 是test-jwt.jks文件，需要在pom.xml中增加不编译过滤（cert文件也一样）
``` xml
<build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-resources-plugin</artifactId>
                <configuration>
                    <nonFilteredFileExtensions>
                        <nonFilteredFileExtension>cert</nonFilteredFileExtension>
                        <nonFilteredFileExtension>jks</nonFilteredFileExtension>
                    </nonFilteredFileExtensions>
                </configuration>
            </plugin>
        </plugins>
    </build>
```
test-jwt.jks的生成,test123为密码，test-jwt.jks放在认证服务器
``` bash
keytool -genkeypair -alias test-jwt -validity 3650 -keyalg RSA -dname "CN=jwt,OU=jtw,O=jtw,L=zurich,S=zurich,C=CH" -keypass test123 -keystore test-jwt.jks -storepass test123
```
### 1.2 JWT的解密需要公钥
``` bash
keytool -list -rfc --keystore test-jwt.jks | openssl x509 -inform pem -pubkey
```
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6b1IZVmJM6R0Y0qLHvME
4n0ce9gToWJcKUzHiExuaLOr6bkYk/lOBeL7NlkNLX7oraU4ej9VZ/onVSldxMVe
7ReVSokxOolllFo1OA1/DImxpnNnClqDftHctiSVhLlFNYh/0PFrhafRaDLGQ7RW
QKCBPPxXjQ+QsaTec3x33oQWENsg/eYIdA4pF7Wnr5rpgH9qXE3BZzw93GzaQBag
Mp/Zv8SCM9jvErcabRnAF97a4wMUk1XTu+9UXk6A0rd7LRNCzwObrVdp6wdt7Rve
eiRbHnNdOT3yGZuJ4S1rzz6e2qxhD/qEPZcR0HBHnJPM0AGS2ota/st9bIc4Y8b3
vQIDAQAB
-----END PUBLIC KEY-----
```
将公钥内容放在一个新建文件中（比如我的叫 public.cert）,公钥放在资源服务器中；

## 2. 修改 SecurityConfiguration
``` java
package com.service.auth.serviceauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers().anyRequest()
                .and()
                .authorizeRequests()
                .antMatchers("/oauth/**").permitAll();
    }
  @Autowired
    UserServiceDetail userServiceDetail;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userServiceDetail).passwordEncoder(passwordEncoder());
    }
}
```
service-auth项目完成了，其它内容和上一篇中的一样。

## 2. 改造service-hi
![v2.png](https://upload-images.jianshu.io/upload_images/2151905-4b6d53b82ec946b7.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/850)
和上面说的一样，pom.xml不用改

### 2.1 application.yml
``` xml
eureka:
  client:
    service-url:
      serviceZone: http://localhost:8761/eureka/
server:
  port: 8765
spring:
  application:
    name: service-hi
  datasource:
      driver-class-name: com.mysql.jdbc.Driver
      url: jdbc:mysql://172.16.10.44:3306/spring-cloud-auth2-db?useUnicode=true&characterEncoding=utf8&characterSetResults=utf8
      username: dev
      password: NHdev2015

  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true

security:
  oauth2:
    resource:
      jwt:
        key-uri: http://localhost:9098/oauth/token_key
    client:
      client-id: client_2
      client-secret: 123456
      access-token-uri: http://localhost:9098/oauth/token
      grant-type: password
      scope: server
      user-authorization-uri: http://localhost:9098/oauth/authorize
```
### 2.2 ResourceServerConfiguration
``` java
package com.service.hi.servicehi.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    @Autowired
    private TokenStore tokenStore;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/product/**","/registry/**", "/user/login/**").permitAll()
                .antMatchers("/**").authenticated();
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.tokenStore(tokenStore);
    }
}

```
### 2.3 新增一个JwtConfig类
``` java
package com.service.hi.servicehi.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;

@Configuration
public class JwtConfig {

    public static final String public_cert = "public.cert";

    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;

    @Bean
    @Qualifier("tokenStore")
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter);
    }

    @Bean
    protected JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        Resource resource =  new ClassPathResource(public_cert);

        String publicKey;
        try {
            publicKey = new String(FileCopyUtils.copyToByteArray(resource.getInputStream()));
        }catch (IOException e) {
            throw new RuntimeException(e);
        }

        converter.setVerifierKey(publicKey);
        return converter;
    }
}
```
### 2.4新增加了一个UserController类其中包含一个login接口
``` java

@RequestMapping("/user")
@RestController
public class UserController {
    @Autowired
    private UserDao userRepository;

    @Autowired
    private OAuth2ClientProperties oAuth2ClientProperties;

    @Autowired
    private OAuth2ProtectedResourceDetails oAuth2ProtectedResourceDetails;

    @Autowired
    private RestTemplate restTemplate;

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @RequestMapping("/login")
    public ResponseEntity<OAuth2AccessToken> login(@Valid UserLoginParamDto loginDto, BindingResult bindingResult) throws Exception {

        if (bindingResult.hasErrors())
            throw new Exception("登录信息错误，请确认后再试");

        User user = userRepository.findByUsername(loginDto.getUsername());

        if (null == user)
            throw new Exception("用户为空，出错了");

        if (!BPwdEncoderUtil.matches(loginDto.getPassword(), user.getPassword().replace("{bcrypt}","")))
            throw new Exception("密码不正确");

        String client_secret = oAuth2ClientProperties.getClientId()+":"+oAuth2ClientProperties.getClientSecret();

        client_secret = "Basic "+Base64.getEncoder().encodeToString(client_secret.getBytes());
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.set("Authorization",client_secret);

        //授权请求信息
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.put("username", Collections.singletonList(loginDto.getUsername()));
        map.put("password", Collections.singletonList(loginDto.getPassword()));
        map.put("grant_type", Collections.singletonList(oAuth2ProtectedResourceDetails.getGrantType()));

        map.put("scope", oAuth2ProtectedResourceDetails.getScope());
        //HttpEntity
        HttpEntity httpEntity = new HttpEntity(map,httpHeaders);
        //获取 Token
        return restTemplate.exchange(oAuth2ProtectedResourceDetails.getAccessTokenUri(), HttpMethod.POST,httpEntity,OAuth2AccessToken.class);

    }
}
```
### 2.5 UserLoginParamDto
``` java
package com.service.hi.servicehi.dto;

import javax.validation.constraints.NotBlank;
import java.io.Serializable;


public class UserLoginParamDto implements Serializable {

    @NotBlank(message = "用户名不能为空")
    private String username;

    @NotBlank(message = "密码不能为空")
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

```
其他的dto类请参看源码，和上一篇一样。
用postman访问user/login接口，http://localhost:8765/user/login?username=user_5&password=123456
``` json
{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1Mzg3MTk1NzgsInVzZXJfbmFtZSI6InVzZXJfNSIsImF1dGhvcml0aWVzIjpbIlVTRVIiLCJST0xFX0FETUlOIiwiQURNSU4iXSwianRpIjoiMTM2NWI3MjYtZjg1YS00OTYyLWFiM2MtYTliZDRlZDhlYzRlIiwiY2xpZW50X2lkIjoiY2xpZW50XzIiLCJzY29wZSI6WyJzZXJ2ZXIiXX0.fPk9JLeZA0YZgqM_eZoh7cQHBtC8uIGW4MyrLOZvyQm2Xv4if1pOGlay3DdSyCdqdTU2v3ycy1qF4CUcLVKv7y-by1WUT51oOAHjkSLbjDHX7Qvn_DA2jNyU_kzJ1Xt36mGCbWhFXfWcT8mdcI_zagEHPrVLOGYts9QpFf4vYIv1RoK5flJfDfzoRBIN_LMJf9eEJS1u_1ciO_HQQJjl7oUyVFDln_aUIdv8fiY5ua-5DqBzFZs292_aWtXmHkC7Ke5PBAv2sR4r0vi4XeXFeQC-8W1WV0JuueujIhtIaKORUni2TlIU01547oH-pzuNL0Sb4XIhpt-F7X7KMhe2Vw",
    "token_type": "bearer",
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJ1c2VyXzUiLCJzY29wZSI6WyJzZXJ2ZXIiXSwiYXRpIjoiMTM2NWI3MjYtZjg1YS00OTYyLWFiM2MtYTliZDRlZDhlYzRlIiwiZXhwIjoxNTM4NzE5NTc4LCJhdXRob3JpdGllcyI6WyJVU0VSIiwiUk9MRV9BRE1JTiIsIkFETUlOIl0sImp0aSI6IjI2NGMxNjA4LTYxMjktNGE1My1iZmJlLWQ1MmM3NjUxNTJhMCIsImNsaWVudF9pZCI6ImNsaWVudF8yIn0.Jxx7NFpjZ4WGM0XXqLuab21uqQ_9BjmDdxqRcPAE8Xq3NP8S_FgI4RHFAqCQbYU_mQ-EGyqeFWRKC3EkrnDijf9Yg29Kjlc_d9fPDR7MIECvVMoqY7FQCjNhTajZHiuEUc2UnPRKhJ1mm9kU045xUQ8HrwQUYNoM08RHbYAsSFS_UlLtfyuImUXD7Mh8xZNNj3r8HFhug9Q5ZajBka0NqcASYSIBq97REv4odaQ0-Djx96UcnARJlyikPOFGsfVeHktVdQ7UTnTLn_sIGyw5Ywy3xw2sr_YV-VMQaFhXQeDJaj5Q2ef4AvahSmfV9V61zlPc1yzfCrv3h16IY9WwEQ",
    "expires_in": 2591998,
    "scope": "server",
    "jti": "1365b726-f85a-4962-ab3c-a9bd4ed8ec4e"
}
```
我想数据库的数据是如何存的这块不用贴出来了吧？
![v3.png](https://upload-images.jianshu.io/upload_images/2151905-4227d55b9cf3b4ea.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
