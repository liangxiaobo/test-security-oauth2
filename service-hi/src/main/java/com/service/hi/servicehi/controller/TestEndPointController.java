package com.service.hi.servicehi.controller;

import com.service.hi.servicehi.dto.UserDao;
import com.service.hi.servicehi.dto.UserLoginDto;
import com.service.hi.servicehi.dto.UserService;
import com.service.hi.servicehi.entity.User;
import com.service.hi.servicehi.utils.BPwdEncoderUtil;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
public class TestEndPointController {

    Logger logger = LoggerFactory.getLogger(TestEndPointController.class);

    @Autowired
    private UserService userService;

    @Autowired
    private UserDao userRepository;

    @GetMapping("/product/{id}")
    public String getProduct(@PathVariable String id) {

        String dbpasswor = "$2a$10$HBX6q6TndkgMxhSEdoFqWOUtctaJEMoXe49NWh8Owc.4MTunv.wXa";

        logger.info("判断两个密码是否相等 " + (BPwdEncoderUtil.matches("123456", dbpasswor)));

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

    @RequestMapping(value = "/registry", method = RequestMethod.POST)
    public User createUser(@RequestParam("username") String username, @RequestParam("password") String password) {
        if (StringUtils.isNotEmpty(username) && StringUtils.isNotEmpty(password)) {
            return userService.create(username, password);
        }

        return null;
    }

    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    @RequestMapping("/hello")
    public String hello() {

        return "hello you";
    }

}
