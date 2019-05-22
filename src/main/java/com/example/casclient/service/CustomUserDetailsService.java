package com.example.casclient.service;

import com.example.casclient.entity.AuthorityInfo;
import com.example.casclient.entity.UserInfo;
import org.jasig.cas.client.validation.Assertion;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.userdetails.*;

import java.util.HashSet;
import java.util.Set;

/**
 * 用于加载用户信息 实现UserDetailsService接口，或者实现AuthenticationUserDetailsService接口
 * @author ChengLi
 *
 */
public class CustomUserDetailsService
  //实现UserDetailsService接口，实现loadUserByUsername方法
 /* implements UserDetailsService {
  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    System.out.println("当前的用户名是："+username);
    //这里我为了方便，就直接返回一个用户信息，实际当中这里修改为查询数据库或者调用服务什么的来获取用户信息
    UserInfo userInfo = new UserInfo();
    userInfo.setUsername("admin");
    userInfo.setName("admin");
    Set<AuthorityInfo> authorities = new HashSet<AuthorityInfo>();
    AuthorityInfo authorityInfo = new AuthorityInfo("TEST");
    authorities.add(authorityInfo);
    userInfo.setAuthorities(authorities);
    return userInfo;
  }*/


        //实现AuthenticationUserDetailsService，实现loadUserDetails方法
        implements AuthenticationUserDetailsService<CasAssertionAuthenticationToken> {

    @Override
    public UserDetails loadUserDetails(CasAssertionAuthenticationToken token) throws UsernameNotFoundException {
        Assertion assertion = token.getAssertion();
        Object credentials = token.getCredentials();
        Object principal = token.getPrincipal();
        Set<AuthorityInfo> authorities = new HashSet<AuthorityInfo>();
        AuthorityInfo authorityInfo1 = new AuthorityInfo("/user/find");
        AuthorityInfo authorityInfo2 = new AuthorityInfo("/");
        AuthorityInfo authorityInfo3 = new AuthorityInfo("/user/delete");
        AuthorityInfo authorityInfo4 = new AuthorityInfo("/login-error");
        AuthorityInfo authorityInfo5 = new AuthorityInfo("/index");

        authorities.add(authorityInfo1);
        authorities.add(authorityInfo2);
        authorities.add(authorityInfo3);
        authorities.add(authorityInfo4);
        authorities.add(authorityInfo5);
//        userInfo.setAuthorities(authorities);
        User user = new User("admin","$2a$10$YOTlCRfmvxtk6PYfODWbJujQ9k/8jF8s/lfdzUr3JgXqtkhwXSHIG",authorities);
//        System.out.println("当前的用户名是："+token.getName());
        //这里我为了方便，就直接返回一个用户信息，实际当中这里修改为查询数据库或者调用服务什么的来获取用户信息
//        UserInfo userInfo = new UserInfo();
//        userInfo.setUsername("admin");
//        userInfo.setName("admin");
//        userInfo.setPassword("admin");


        return user;
    }

}
