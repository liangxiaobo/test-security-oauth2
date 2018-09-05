package com.service.hi.servicehi.utils;


import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BPwdEncoderUtil {
    private static final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
//    public static String BCryptPassword(String password) {
//        return passwordEncoder.encode(password);
//    }

    public static boolean matches(CharSequence rawPassword, String encodedPassword){
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }
}
