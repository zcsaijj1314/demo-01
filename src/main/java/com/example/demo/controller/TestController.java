package com.example.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
/**
 * 现在我们配置了相关角色才能访问的路径，那么现在就测试一下，an拥有admin角色，可以访问/admin/**和/user/**,an2拥有user角色，只能访问/user/**
 * */
@RestController
public class TestController {
    @GetMapping("/hello")
    public String hello() {
        return "hello ananan";
    }
    @GetMapping("/admin/hello")
    public String admin() {
        return "hello admin";
    }
    @GetMapping("/user/hello")
    public String user() {
        return "hello user";
    }
}
