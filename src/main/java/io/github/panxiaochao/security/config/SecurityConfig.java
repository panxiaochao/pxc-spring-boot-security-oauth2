package io.github.panxiaochao.security.config;

import io.github.panxiaochao.security.constant.SecurityConstants;
import io.github.panxiaochao.security.crypto.PasswordEncoderFactory;
import io.github.panxiaochao.security.properties.OAuth2SelfProperties;
import io.github.panxiaochao.security.service.UserDetailServiceImpl;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.annotation.Resource;

/**
 * {@code SecurityConfig}
 * <p>
 *
 * @author Lypxc
 * @since 2022/7/15
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger LOGGER = LogManager.getLogger(SecurityConfig.class);

    @Resource
    private OAuth2SelfProperties selfProperties;

    /**
     * 自定义 UserDetailsService
     */
    @Bean
    public UserDetailsService userDetailService() {
        return new UserDetailServiceImpl();
    }

    /**
     * 自定义密码模式-MD5 模式
     *
     * @return PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactory.getInstance(selfProperties.getAlgorithm());
    }

    /**
     * Security过滤器链
     *
     * @param httpSecurity
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        LOGGER.info(">>> 自定义 DefaultSecurityFilterChain 配置");
        // 基础配置
        httpSecurity
                // cors
                .cors().and()
                // CSRF禁用，因为不使用session
                .csrf().disable()
                // 防止iframe 造成跨域
                .headers().frameOptions().disable().and()
                // 基于token，所以不需要session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                // 禁用缓存
                .headers().cacheControl();
        // 过滤请求
        httpSecurity.authorizeHttpRequests(authorize ->
                authorize
                        // 只放行OAuth相关接口
                        .antMatchers(SecurityConstants.TOKEN_ENDPOINT).permitAll()
                        // 除上面外的所有请求全部需要鉴权认证
                        .anyRequest().authenticated()
        );
        return httpSecurity.build();
    }
}
