package com.example.casclient.config;

import com.example.casclient.service.CustomUserDetailsService;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.validation.Cas20ProxyTicketValidator;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)  //  启用方法级别的权限认证
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CasProperties casProperties;


    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**");
        web.ignoring().antMatchers("/images/**");
        web.ignoring().antMatchers("/js/**");
//忽略登录界面
//        web.ignoring().antMatchers("/login");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //  允许所有用户访问"/"和"/index.html"
        http.authorizeRequests()// 配置安全策略
                .antMatchers("/").permitAll()
                .and().authorizeRequests().anyRequest().authenticated()
                .and().logout().permitAll();// 定义logout不需要验证
//                .and().formLogin().defaultSuccessUrl("/login"); // 登录成功之后的跳转
        http.exceptionHandling().authenticationEntryPoint(casAuthenticationEntryPoint())
                .and().addFilter(casAuthenticationFilter())
                .addFilterBefore(casLogoutFilter(), LogoutFilter.class)
                .addFilterBefore(singleSignOutFilter(), CasAuthenticationFilter.class);

        http.csrf().disable();

        // 关闭spring security默认的frame访问限制
        http.headers().frameOptions().sameOrigin();
    }

    // @formatter:off
//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
////        super.configure(auth);
//        auth.authenticationProvider(casAuthenticationProvider());
//    }
    // @formatter:on


    // @formatter:off

    /**
     * 1.认证的入口，spring security 拦截用户的请求,如果验证没有通过，然后定向到 cas服务器
     */
    @Bean
    public CasAuthenticationEntryPoint casAuthenticationEntryPoint() {
        System.err.println("认证的入口" + casProperties.getCasServerLoginUrl());

        CasAuthenticationEntryPoint casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
        casAuthenticationEntryPoint.setServiceProperties(serviceProperties());
        casAuthenticationEntryPoint.setLoginUrl(casProperties.getCasServerLoginUrl());
        return casAuthenticationEntryPoint;
    }
    // @fomatter:on


    /**
     * 指定service相关信息
     */
    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties serviceProperties = new ServiceProperties();
        System.err.println("指定service相关信息" + casProperties.getAppServerUrl() + casProperties.getAppLoginUrl());
        serviceProperties.setService(casProperties.getAppServerUrl() + casProperties.getAppLoginUrl());
//        serviceProperties.setAuthenticateAllArtifacts(true);//代理票据模式时使用
//        serviceProperties.setSendRenew(false);
        return serviceProperties;
    }

    /**
     * 2.CAS认证过滤器。认证通过跳转回 web服务器后，需要使用此过滤器监听、 设置的 url，如果是，则处理url请求
     */
    @Bean
    public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
        CasAuthenticationFilter casAuthenticationFilter = new CasAuthenticationFilter();
        casAuthenticationFilter.setAuthenticationManager(authenticationManager());
        System.err.println("CAS认证过滤器" + casProperties.getAppLoginUrl());
        casAuthenticationFilter.setFilterProcessesUrl(casProperties.getAppLoginUrl());
        return casAuthenticationFilter;
    }

    /**
     * 3。cas 认证 Provider。第二步使用authenticationManager()进行认证，而authenticationManager的实现类ProviderManager，却引用的是下面的方法。
     */
    @Bean
    public CasAuthenticationProvider casAuthenticationProvider() {
        CasAuthenticationProvider provider = new CasAuthenticationProvider();
        provider.setServiceProperties(serviceProperties());
        provider.setAuthenticationUserDetailsService(customUserDetailsService());
        //casAuthenticationProvider.setUserDetailsService(customUserDetailsService()); //这里只是接口类型，实现的接口不一样，都可以的。
        provider.setTicketValidator(cas20ServiceTicketValidator());

        provider.setKey("casProvider");
        return provider;
    }

  /*@Bean
  public UserDetailsService customUserDetailsService(){
    return new CustomUserDetailsService();
  }*/

    /**
     * 用户自定义的AuthenticationUserDetailsService，第三部加载凭证时使用，主要是回调获取返回结果
     */
    @Bean
    public AuthenticationUserDetailsService<CasAssertionAuthenticationToken> customUserDetailsService() {
        return new CustomUserDetailsService();
    }

    /**
     * 4.验证 ticket. 返回的 ticket，web服务器需要想 cas 服务器确认是否时有效的。使用下面的方法.处理完成后返回第三步的方法中，继续执行
     * @return
     */
    @Bean
    public Cas20ServiceTicketValidator cas20ServiceTicketValidator() {
        System.err.println("Cas20ServiceTicketValidator" + casProperties.getCasServerUrl());
        return new Cas20ServiceTicketValidator(casProperties.getCasServerUrl());
    }
//    @Bean
//    public Cas20ProxyTicketValidator cas20ServiceTicketValidator() {
//        System.err.println("Cas20ServiceTicketValidator" + casProperties.getCasServerUrl());
//        return new Cas20ProxyTicketValidator(casProperties.getCasServerUrl());
//    }

    /**
     * 单点登出过滤器
     */
    @Bean
    public SingleSignOutFilter singleSignOutFilter() {
        SingleSignOutFilter singleSignOutFilter = new SingleSignOutFilter();
        singleSignOutFilter.setCasServerUrlPrefix(casProperties.getCasServerUrl());
        singleSignOutFilter.setIgnoreInitConfiguration(true);
        return singleSignOutFilter;
    }

    /**
     * 请求单点退出过滤器
     */
    @Bean
    public LogoutFilter casLogoutFilter() {
        LogoutFilter logoutFilter = new LogoutFilter(casProperties.getCasServerLogoutUrl(), new SecurityContextLogoutHandler());
        logoutFilter.setFilterProcessesUrl(casProperties.getAppLogoutUrl());
        return logoutFilter;
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
    }
}
