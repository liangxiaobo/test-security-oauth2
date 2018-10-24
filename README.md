
* **master分支是当前文章的项目**
* **master-jdbc分支 是在master基础上以mysql数据库的实现**
* **master-jwt分支 是在oauth2 jwt的实现**

* 二、[Spring Cloud OAuth2 token存数据库实现](https://www.jianshu.com/p/4ce5577bab74)
* 三、[Spring Cloud Oauth2 JWT 实现](https://www.jianshu.com/p/402bda62a7c3)

学习一下Spring Cloud OAuth2，我们分三个项目 eureka-server、service-auth、service-hi

 ![g9.png](https://upload-images.jianshu.io/upload_images/2151905-98b8ab75251c922d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


# 1. 创建eureka-server项目
选择依赖 **spring-cloud-starter-netflix-eureka-server**
## 1.1 启动类里添加注释
``` java
@SpringBootApplication
@EnableEurekaServer
public class EurekaServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(EurekaServerApplication.class, args);
    }
}
```
## 1.2 application.yml
``` xml
spring:
  application:
    name: eureka-server
server:
  port: 8761
eureka:
  instance:
    hostname: localhost
  client:
    service-url:
      defaultZone: http://localhost:8761/eureka/
    fetch-registry: false
    register-with-eureka: false
```
配置完成可以访问 http://localhost:8761

#2 创建service-auth项目
## 2.1 用于获取授权token，项目上目录结构：
![g4.png](https://upload-images.jianshu.io/upload_images/2151905-82f360b00e6ae1c2.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

> 这里有个有趣的地方，如果包名config和customImpl和启动类不在同一个根包下，会扫不到包，此时必须在启动类上增加 ``` @ComponentScan(basePackages = "包名") ```

##2.2 创建项目依赖 
+ **spring-boot-starter-data-redis** 把token存到redis中
+ **spring-cloud-starter-netflix-eureka-client** 做为EurekaClient
+ **spring-cloud-starter-oauth2** 是对spring-cloud-starter-security、spring-security-oauth2、spring-security-jwt这3个依赖的整合
+ **spring-boot-starter-actuator**

完整pom.xml
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.uaa.service</groupId>
    <artifactId>uaa-service</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <packaging>jar</packaging>

    <name>uaa-service</name>
    <description>Demo project for Spring Boot</description>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.0.4.RELEASE</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>

    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
        <java.version>1.8</java.version>
        <spring-cloud.version>Finchley.SR1</spring-cloud.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-oauth2</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-dependencies</artifactId>
                <version>${spring-cloud.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>


</project>
```
## 2.3 application.yml 
```xml
spring:
  application:
    name: service-auth
  redis:
    host: 172.16.10.43
    database: 0
server:
  port: 9098
eureka:
  client:
    service-url:
      defaultZone: http://localhost:8761/eureka/
```
application.yml中配置redis、注册中心
接下来分别继承 **AuthorizationServerConfigurerAdapter**和**WebSecurityConfigurerAdapter**
+ AuthorizationServerConfigurerAdapter 类中3个不同的configure方法分别
  + configure(ClientDetailsServiceConfigurer clients) 用来配置客户端详情服务（ClientDetailsService），客户端详情信息在这里进行初始化，你能够把客户端详情信息写死在这里或者是通过数据库来存储调取详情信息；
  + configure(AuthorizationServerEndpointsConfigurer endpoints) 用来配置授权（authorization）以及令牌（token）的访问端点和令牌服务(token services)，还有token的存储方式(tokenStore)；
  + configure(AuthorizationServerSecurityConfigurer security) 用来配置令牌端点(Token Endpoint)的安全约束；
+ WebSecurityConfigurerAdapter 
  + configure(HttpSecurity http) httpSecurity中配置所有请求的安全验证
  + 注入Bean UserDetailsService
  + 注入Bean AuthenticationManager 用来做验证
  + 注入Bean PasswordEncoder

## 2.4  AuthorizationServerConfiguration继承AuthorizationServerConfigurerAdapter
``` java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    RedisConnectionFactory redisConnectionFactory;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        String finalSecret = "{bcrypt}" + new BCryptPasswordEncoder().encode("123456");

        // 配置两个客户端，一个用于password认证一个用于client认证
        clients.inMemory().withClient("client_1")
                .resourceIds(Utils.RESOURCEIDS.ORDER)
                .authorizedGrantTypes("client_credentials", "refresh_token")
                .scopes("select")
                .authorities("oauth2")
                .secret(finalSecret)
                .and().withClient("client_2")
                .resourceIds(Utils.RESOURCEIDS.ORDER)
                .authorizedGrantTypes("password", "refresh_token")
                .scopes("server")
                .authorities("oauth2")
                .secret(finalSecret);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(new MyRedisTokenStore(redisConnectionFactory))
                .authenticationManager(authenticationManager)
                .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // 允许表单认证
        security.allowFormAuthenticationForClients();
    }
}


```
##2.5 SecurityConfiguration 继承 WebSecurityConfigurerAdapter
``` java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

        String finalPassword = "{bcrypt}"+bCryptPasswordEncoder.encode("123456");
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("user_1").password(finalPassword).authorities("USER").build());
        manager.createUser(User.withUsername("user_2").password(finalPassword).authorities("USER").build());

        return manager;
    }

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

> 这里在内在中创建了两个用户user_1和user_2，后续会以存mysql数据的方式来完善。

##2.6 暴露Remote Token Services 接口
采用RemoteTokenServices这种方式对token进行验证，如果其他资源服务需要验证token,则需要远程调用授权服务暴露的验证token的api接口，验证token的API接口代码如下：

``` java
@RestController
@RequestMapping("/users")
public class UserController {

    Logger logger = LoggerFactory.getLogger(UserController.class);

    @RequestMapping(value = "/current", method = RequestMethod.GET)
    public Principal getUser(Principal principal) {
        logger.info(">>>>>>>>>>>>>>>>>>>>>>>>");
        logger.info(principal.toString());
        logger.info(">>>>>>>>>>>>>>>>>>>>>>>>");
        return principal;
    }
}

```
 

##2.7 启动类
``` java
@SpringBootApplication
@EnableResourceServer
@EnableEurekaClient
public class ServiceAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(ServiceAuthApplication.class, args);
    }
}
```
> 启动类上加上EnableResourceServer注解开启资源服务，因为程序需要对外暴露获取token的API和验证token的API所以该程序也是一个资源服务器。

*到此，授权服务已经配置完成，可以访问，认证类型以password方式*

![g2.png](https://upload-images.jianshu.io/upload_images/2151905-1fb916316cb390c5.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

# 3. 创建资源服务器 service-hi
创建项目的依赖 spring-cloud-starter-openfeign、spring-cloud-starter-oauth2、spring-cloud-starter-netflix-eureka-client、spring-boot-starter-web
## 3.1 以下是完整pom.xml
``` xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>

	<groupId>com.service.hi</groupId>
	<artifactId>service-hi</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<packaging>jar</packaging>

	<name>service-hi</name>
	<description>Demo project for Spring Boot</description>

	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.0.4.RELEASE</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>

	<properties>
		<project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
		<project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
		<java.version>1.8</java.version>
		<spring-cloud.version>Finchley.SR1</spring-cloud.version>
	</properties>

	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-oauth2</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-openfeign</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
	</dependencies>

	<dependencyManagement>
		<dependencies>
			<dependency>
				<groupId>org.springframework.cloud</groupId>
				<artifactId>spring-cloud-dependencies</artifactId>
				<version>${spring-cloud.version}</version>
				<type>pom</type>
				<scope>import</scope>
			</dependency>
		</dependencies>
	</dependencyManagement>

	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
			</plugin>
		</plugins>
	</build>


</project>
```

## 3.2 配置文件 application.yml
``` xml
eureka:
  client:
    service-url:
      defaultZone: http://localhost:8761/eureka/
server:
  port: 8765
spring:
  application:
    name: service-hi
security:
  oauth2:
    resource:
      user-info-uri: http://localhost:9098/users/current
    client:
      id: client_2
      client-secret: 123456
      access-token-uri: http://localhost:9098/oauth/token
      grant-type: client_credentials,password
      scope: server
```
> security.oauth2.resource.user-info-uri用于获取当前token的用户信息，配置security.oauth2.client的相关信息以及clientId、client-secret等信息要和service-auth中的配置一一对应。

## 3.3 配置Resource Server
``` java
@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {


    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/order/**").authenticated(); // 配置order访问控制，必须认证后才可以访问
    }
}
```
> 添加EnableResourceServer注解开启资源服务的功能，加注解EnableGlobalMethodSecurity开户方法级别的保护，ResourceServerConfigurerAdapter是配置类，configure(HttpSecurity http)中只配置了"/order/**"需要验证。

## 3.4 配置OAuth2 Client
OAuth2 client用来访问被OAuth2保护的资源，service-hi作为OAuth2 Client，配置如下：
``` java
@EnableOAuth2Client
@EnableConfigurationProperties
@Configuration
public class OAuth2ClientConfig {

    @Bean
    @ConfigurationProperties(prefix = "security.oauth2.client")
    public ClientCredentialsResourceDetails clientCredentialsResourceDetails() {
        return new ClientCredentialsResourceDetails();
    }

    @Bean
    public RequestInterceptor oauth2FeignRequestInterceptor() {
        return new OAuth2FeignRequestInterceptor(new DefaultOAuth2ClientContext(), clientCredentialsResourceDetails());
    }

    @Bean
    public OAuth2RestTemplate clientCredentialsRestTemplate() {
        return new OAuth2RestTemplate(clientCredentialsResourceDetails());
    }
}
```
> 注解EnableOAuth2Client开启了OAuth2 Client功能，注入一个OAuth2RestTemplate 类型的Bean用于向service-auth服务请求。
## 3.5 写一个端点测试Controller TestEndPointController
``` java
@RestController
public class TestEndPointController {

    Logger logger = LoggerFactory.getLogger(TestEndPointController.class);

    @GetMapping("/product/{id}")
    public String getProduct(@PathVariable String id) {
        return "product id : " + id;
    }

    @GetMapping("/order/{id}")
    public String getOrder(@PathVariable String id) {
        return "order id : " + id;
    }

    @GetMapping("/getPrinciple")
    public OAuth2Authentication getPrinciple(OAuth2Authentication oAuth2Authentication, Principal principal, Authentication authentication) {
        logger.info(oAuth2Authentication.getUserAuthentication().getAuthorities().toString());
        logger.info(oAuth2Authentication.toString());
        logger.info("principal.toString() " + principal.toString());
        logger.info("principal.getName() " + principal.getName());
        logger.info("authentication: " + authentication.getAuthorities().toString());

        return oAuth2Authentication;
    }
}
```
## 3.6 启动类
``` java
@SpringBootApplication
@EnableEurekaClient
public class ServiceHiApplication {

	public static void main(String[] args) {
		SpringApplication.run(ServiceHiApplication.class, args);
	}
}
```
到此资源服务的配置也完成，我们可以测试，依次启动 eureka-server、service-auth、service-hi
访问http://localhost:8761
![g7.png](https://upload-images.jianshu.io/upload_images/2151905-75e9f3ced3a578b8.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/850)

访问oauth/token获取token信息 get方式请求： 

http://localhost:9098/oauth/token?username=user_1&password=123456&grant_type=password&scope=server&client_id=client_2&client_secret=123456

也可以使用postman用post方式访问。
请求结果：
``` json
{
    "access_token": "e9a93dff-fd58-4af3-b458-01fbb6079416",
    "token_type": "bearer",
    "refresh_token": "f31290cf-f421-49ba-8112-95a1a2fe9f09",
    "expires_in": 40172,
    "scope": "server"
}
```
这时候如果访问service-hi的http://localhost:8765/order/1 不带token信息：
``` json
{
    "error": "unauthorized",
    "error_description": "Full authentication is required to access this resource"
}
```
告诉你，没有权限访问该资源

正确的访问姿势：
可以是以url参数形式 http://localhost:8765/order/1?access_token=e9a93dff-fd58-4af3-b458-01fbb6079416
也可以是headers 的authorization中 bearer token 形式
![g8.png](https://upload-images.jianshu.io/upload_images/2151905-f24eb03adf19d26d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/850)

不需要验证的资源product  http://localhost:8765/product/1
```
product id : 1
```
getPrinciple打印出验证信息 http://localhost:8765/getPrinciple ：
``` json
{
    "authorities": [
        {
            "authority": "USER"
        }
    ],
    "details": {
        "remoteAddress": "0:0:0:0:0:0:0:1",
        "sessionId": "8F2D30BA614CA41B6AA03D2A4650EA3E",
        "tokenValue": "e9a93dff-fd58-4af3-b458-01fbb6079416",
        "tokenType": "Bearer",
        "decodedDetails": null
    },
    "authenticated": true,
    "userAuthentication": {
        "authorities": [
            {
                "authority": "USER"
            }
        ],
        "details": {
            "authorities": [
                {
                    "authority": "USER"
                }
            ],
            "details": {
                "remoteAddress": "127.0.0.1",
                "sessionId": null,
                "tokenValue": "e9a93dff-fd58-4af3-b458-01fbb6079416",
                "tokenType": "Bearer",
                "decodedDetails": null
            },
            "authenticated": true,
            "userAuthentication": {
                "authorities": [
                    {
                        "authority": "USER"
                    }
                ],
                "details": {
                    "grant_type": "password",
                    "scope": "server",
                    "client_secret": "123456",
                    "client_id": "client_2",
                    "username": "user_1"
                },
                "authenticated": true,
                "principal": {
                    "password": null,
                    "username": "user_1",
                    "authorities": [
                        {
                            "authority": "USER"
                        }
                    ],
                    "accountNonExpired": true,
                    "accountNonLocked": true,
                    "credentialsNonExpired": true,
                    "enabled": true
                },
                "credentials": null,
                "name": "user_1"
            },
            "oauth2Request": {
                "clientId": "client_2",
                "scope": [
                    "server"
                ],
                "requestParameters": {
                    "grant_type": "password",
                    "scope": "server",
                    "client_id": "client_2",
                    "username": "user_1"
                },
                "resourceIds": [],
                "authorities": [
                    {
                        "authority": "oauth2"
                    }
                ],
                "approved": true,
                "refresh": false,
                "redirectUri": null,
                "responseTypes": [],
                "extensions": {},
                "grantType": "password",
                "refreshTokenRequest": null
            },
            "principal": {
                "password": null,
                "username": "user_1",
                "authorities": [
                    {
                        "authority": "USER"
                    }
                ],
                "accountNonExpired": true,
                "accountNonLocked": true,
                "credentialsNonExpired": true,
                "enabled": true
            },
            "credentials": "",
            "clientOnly": false,
            "name": "user_1"
        },
        "authenticated": true,
        "principal": "user_1",
        "credentials": "N/A",
        "name": "user_1"
    },
    "clientOnly": false,
    "principal": "user_1",
    "credentials": "",
    "oauth2Request": {
        "clientId": null,
        "scope": [],
        "requestParameters": {},
        "resourceIds": [],
        "authorities": [],
        "approved": true,
        "refresh": false,
        "redirectUri": null,
        "responseTypes": [],
        "extensions": {},
        "grantType": null,
        "refreshTokenRequest": null
    },
    "name": "user_1"
}
```

