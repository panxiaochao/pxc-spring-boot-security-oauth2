package io.github.panxiaochao.security.config;

import io.github.panxiaochao.security.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationProvider;
import io.github.panxiaochao.security.service.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import javax.annotation.Resource;

/**
 * {@code ResourceOwnerPasswordAuthenticationConfig}
 * <p> description:
 *
 * @author Lypxc
 * @since 2022-12-16
 */
@Configuration
public class OAuth2CustomAuthenticationConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2CustomAuthenticationConfig.class);

    @Resource
    private UserDetailsServiceImpl userDetailService;

    @Resource
    private PasswordEncoder passwordEncoder;

    @Resource
    private OAuth2AuthorizationService authorizationService;

    @Resource
    private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    @Bean
    public OAuth2ResourceOwnerPasswordAuthenticationProvider resourceOwnerPasswordAuthenticationProvider() {
        LOGGER.info(">>> 自定义 OAuth2ResourceOwnerPasswordAuthenticationProvider 配置");
        return new OAuth2ResourceOwnerPasswordAuthenticationProvider(userDetailService, passwordEncoder, authorizationService, tokenGenerator);
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        LOGGER.info(">>> 自定义 DaoAuthenticationProvider 配置");
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        daoAuthenticationProvider.setUserDetailsService(userDetailService);
        return daoAuthenticationProvider;
    }


}
