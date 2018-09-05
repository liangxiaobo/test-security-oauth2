package com.service.hi.servicehi;

import com.service.hi.servicehi.entity.JWT;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(value = "service-auth")
public interface AuthServiceClient {
//    @PostMapping(value = "/oauth/token")
//    JWT getToken(@RequestHeader(value = "Authorization") String authorization, @RequestParam("grant_type") String type, @RequestParam("username") String username,
//                 @RequestParam("password") String password,@RequestParam("scope") String scope, @RequestParam("client_id") String client_id);

    @PostMapping(value = "/oauth/token")
    JWT getToken(@RequestHeader(value = "Authorization") String authorization, @RequestParam("grant_type") String type, @RequestParam("username") String username,
                 @RequestParam("password") String password);
}
