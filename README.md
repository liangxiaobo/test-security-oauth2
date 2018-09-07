> 本文是基于上一篇 [Spring Cloud OAuth2教程](https://www.jianshu.com/p/3427549a148a) 实现的token入库，并且用户从数据库中读取；
源码地址：https://github.com/liangxiaobo/test-security-oauth2/tree/master-jdbc 注意是分支master-jdbc

## 1 改造service-auth项目
### 1.1 添加pom依赖
``` xml
       <dependency>
          <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <scope>runtime</scope>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
```
### 1.2 application.yml添加数据库配置
``` xml
spring:
  application:
    name: service-auth

  datasource:
      driver-class-name: com.mysql.jdbc.Driver
      url: jdbc:mysql://172.16.10.44:3306/spring-cloud-auth2-db?useUnicode=true&characterEncoding=utf8&characterSetResults=utf8
      username: dev
      password: NHdev2015

  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true

  后面的省略......
```
### 1.3 修改 AuthorizationServerConfiguration类
``` java

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    RedisConnectionFactory redisConnectionFactory;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private UserServiceDetail userServiceDetail;

    @Autowired
    private ClientDetailsService clientDetailsService;

    static final Logger logger = LoggerFactory.getLogger(AuthorizationServerConfiguration.class);

    @Bean
    public TokenStore tokenStore() {
        return new JdbcTokenStore(dataSource);
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
        // redisTokenStore
//        endpoints.tokenStore(new MyRedisTokenStore(redisConnectionFactory))
//                .authenticationManager(authenticationManager)
//                .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);

        // 存数据库
        endpoints.tokenStore(tokenStore).authenticationManager(authenticationManager)
                .userDetailsService(userServiceDetail);

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
> 其中 增加的Bean分别有dataSource, tokenStore, clientDetailsService, userServiceDetail，修改了ClientDetailsServiceConfigurer，AuthorizationServerEndpointsConfigurer
#### 1.3.1 tokenStore

``` java
@Bean
    public TokenStore tokenStore() {
        return new JdbcTokenStore(dataSource);
    }
```
#### 1.3.2 clientDetailsService
``` java
@Bean // 声明 ClientDetails实现
    public ClientDetailsService clientDetailsService() {
        return new JdbcClientDetailsService(dataSource);
    }
```
#### 1.3.3 userServiceDetail 
userServiceDetail是```org.springframework.security.core.userdetails.UserDetailsService```的自定义实现
``` java
@Service
public class UserServiceDetail  implements UserDetailsService {

    @Autowired
    private UserDao userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username);
    }
}
```
UserDao 继承了JpaRepository
``` java
public interface UserDao extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
```
User类
``` java
@Entity
public class User implements UserDetails, Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column
    private String password;

    @ManyToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinTable(name = "user_role", joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"))
    private List<Role> authorities;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setAuthorities(List<Role> authorities) {
        this.authorities = authorities;
    }



    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

```
Role类
``` java
@Entity
public class Role implements GrantedAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }


    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String getAuthority() {
        return name;
    }

    @Override
    public String toString() {
        return "Role{" +
                "id=" + id +
                ", name='" + name + '\'' +
                '}';
    }
}
```
### 1.4 改造 SecurityConfiguration 类
``` java

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        AuthenticationManager manager = super.authenticationManagerBean();
        return manager;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers().anyRequest()
                .and()
                .authorizeRequests()
                .antMatchers("/oauth/**").permitAll();
    }
}
```
到此service-auth项目改造完成，这里有一个官方提供的oauth2相关的数据库脚本
https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/test/resources/schema.sql 官方给的不能直接创建，需要修改，把主键长度256改为128,把LONGVARBINARY类型改为BLOB，下面是我改好的:

**schema.sql**
``` sql
-- used in tests that use HSQL
create table oauth_client_details (
  client_id VARCHAR(128) PRIMARY KEY,
  resource_ids VARCHAR(128),
  client_secret VARCHAR(128),
  scope VARCHAR(128),
  authorized_grant_types VARCHAR(128),
  web_server_redirect_uri VARCHAR(128),
  authorities VARCHAR(128),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information VARCHAR(4096),
  autoapprove VARCHAR(128)
);

create table oauth_client_token (
  token_id VARCHAR(128),
  token BLOB,
  authentication_id VARCHAR(128) PRIMARY KEY,
  user_name VARCHAR(128),
  client_id VARCHAR(128)
);

create table oauth_access_token (
  token_id VARCHAR(128),
  token BLOB,
  authentication_id VARCHAR(128) PRIMARY KEY,
  user_name VARCHAR(128),
  client_id VARCHAR(128),
  authentication BLOB,
  refresh_token VARCHAR(128)
);

create table oauth_refresh_token (
  token_id VARCHAR(128),
  token BLOB,
  authentication BLOB
);

create table oauth_code (
  code VARCHAR(128), authentication BLOB
);

create table oauth_approvals (
	userId VARCHAR(128),
	clientId VARCHAR(128),
	scope VARCHAR(128),
	status VARCHAR(10),
	expiresAt TIMESTAMP,
	lastModifiedAt TIMESTAMP
);


-- customized oauth_client_details table
create table ClientDetails (
  appId VARCHAR(128) PRIMARY KEY,
  resourceIds VARCHAR(128),
  appSecret VARCHAR(128),
  scope VARCHAR(128),
  grantTypes VARCHAR(128),
  redirectUrl VARCHAR(128),
  authorities VARCHAR(128),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additionalInformation VARCHAR(4096),
  autoApproveScopes VARCHAR(128)
);

```
看数据库的数据存储 表oauth_client_details
![k1.png](https://upload-images.jianshu.io/upload_images/2151905-2589c3ae08c6579e.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

> 还缺少用户信息，用户会在service-hi中创建；

## 2 改造service-hi项目
这个项目改造的比较简单就是如果创建一个用户到数据库

### 2.1 pom添加依赖
``` xml
<dependency>
	<groupId>mysql</groupId>
	<artifactId>mysql-connector-java</artifactId>
	<scope>runtime</scope>
</dependency>

<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
```
### 2.2 application.yml 在原有的基础上添加
``` xml
  datasource:
      driver-class-name: com.mysql.jdbc.Driver
      url: jdbc:mysql://172.16.10.44:3306/spring-cloud-auth2-db?useUnicode=true&characterEncoding=utf8&characterSetResults=utf8
      username: 用户名
      password: 密码

  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
```
### 2.3 在TestEndPointController中添加一个接口 registry
``` java
@RequestMapping(value = "/registry", method = RequestMethod.POST)
    public User createUser(@RequestParam("username") String username, @RequestParam("password") String password) {
        if (StringUtils.isNotEmpty(username) && StringUtils.isNotEmpty(password)) {
            return userService.create(username, password);
        }

        return null;
    }
```
> Bean userService是数据库访问层的实现；

### 2.4 定义接口 UserService
``` java
public interface UserService {
    public User create(String username, String password);
}
```
### 2.5 UserService的实现UserServiceImpl
``` java
@Service
public class UserServiceImpl implements UserService {

    private static final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Autowired
    private UserDao userDao;

    @Override
    public User create(String username, String password) {
        User user = new User();
        user.setUsername(username);
        password = "{bcrypt}" + passwordEncoder.encode(password);
        user.setPassword(password);
        User u = userDao.save(user);
        return u;
    }
}
```
### 2.6 User，Role
> 和上面的User,Role一样

配置都以完成，可以测试了，依次启动eureka-server、service-auth、service-hi
访问 http://localhost:8765/registry 提交表单
![k2.png](https://upload-images.jianshu.io/upload_images/2151905-23d7629ee20a7c52.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
现在数据库的user表中多了一个用户,然后拿用户去请求token
访问 http://localhost:9098/oauth/token
![k3.png](https://upload-images.jianshu.io/upload_images/2151905-cb6cd53d449f1ce1.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

> 注意到密码为什么是```{bcrypt}$2a$10$7qkIuNV0gLeCX8XVILhC3e0kVSNH0.kfLqYlk79vwwozb8YMAkhLi```，我找了一个别人写的博客 https://www.cnkirito.moe/spring-security-6/
官方文档 https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#core-services-password-encoding
![k5.png](https://upload-images.jianshu.io/upload_images/2151905-54f77bf55a77a5fb.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


喜欢的朋友请赞赏支持一下
