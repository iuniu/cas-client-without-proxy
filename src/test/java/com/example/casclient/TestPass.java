package com.example.casclient;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class TestPass {
    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        String admin = encoder.encode("admin");
        System.err.println(admin);
    }
}
