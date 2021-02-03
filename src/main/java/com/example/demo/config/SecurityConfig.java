package com.example.demo.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class SecurityConfig extends  WebSecurityConfigurerAdapter {
    @Bean
    PasswordEncoder passwordEncoder(){//密码加密注入
        return new BCryptPasswordEncoder();
    }
    /**
     * 在内存中添加用户和密码并赋予权限
     * */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("an")
                .password("$2a$10$xAcjyGL.09bV7wJmRYm3e.QrNnlH5dP7TevGn98DUwjU.kv6yF.bu")
                .roles("admin")
                .and()
                .withUser("an2")
                .password("$2a$10$xAcjyGL.09bV7wJmRYm3e.QrNnlH5dP7TevGn98DUwjU.kv6yF.bu")
                .roles("user");
    }
    /**
     * 配置拦截路径
     * */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("admin") // admin角色才能访问
                .antMatchers("/user/**").hasAnyRole("admin","user") // admin或user角色才能访问
                .anyRequest().authenticated()  // 其他接口认证只有即可访问
                .and()
                .formLogin()// 登录表单
                .loginProcessingUrl("/doLogin") // 处理登录的url
                //登录成功处理handler，返回一段json
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse res, Authentication auth) throws IOException, ServletException {
                        res.setContentType("application/json;charset=utf-8");
                        PrintWriter out = res.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("status", 200);
                        map.put("msg", auth.getPrincipal());  // 登录成功的对象
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                // 登录失败处理handler，返回一段json
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest req, HttpServletResponse res, AuthenticationException e) throws IOException, ServletException {
                        res.setContentType("application/json;charset=utf-8");
                        PrintWriter out = res.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("status", 401);
                        if (e instanceof LockedException) {
                            map.put("msg", "账户被锁定，登录失败！");
                        } else if (e instanceof BadCredentialsException) {
                            map.put("msg", "用户名或密码输入错误，登录失败！");
                        } else if (e instanceof DisabledException) {
                            map.put("msg", "账户被禁用，登录失败！");
                        } else if (e instanceof AccountExpiredException) {
                            map.put("msg", "账户过期，登录失败！");
                        } else if (e instanceof CredentialsContainer) {
                            map.put("msg", "密码过期，登录失败");
                        } else {
                            map.put("msg", "登录失败！");
                        }
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                .and()
                .logout()
                .logoutUrl("/logout")
                //退出登录成功的处理器
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse resp, Authentication authentication) throws IOException, ServletException {
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("status", 200);
                        map.put("msg", "注销登录成功!");
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                .permitAll() // 跟登录相关的直接通过
                .and()
                .csrf().disable(); // 关闭防止csrf攻击，方便测试
    }
}
