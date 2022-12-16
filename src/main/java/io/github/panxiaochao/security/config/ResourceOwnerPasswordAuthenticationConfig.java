package io.github.panxiaochao.security.config;

import io.github.panxiaochao.security.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationProvider;
import io.github.panxiaochao.security.service.UserDetailServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
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
public class ResourceOwnerPasswordAuthenticationConfig {

    /**
     * 自定义 UserDetailsService
     */
    @Resource
    private UserDetailServiceImpl userDetailService;

    @Resource
    private PasswordEncoder passwordEncoder;

    @Resource
    private OAuth2AuthorizationService authorizationService;

    @Resource
    private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    /**
     * @param builder
     * @throws Exception
     */
    @Resource
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {
        builder.authenticationProvider(oAuth2ResourceOwnerPasswordAuthenticationProvider())
                .userDetailsService(userDetailService)
                .passwordEncoder(passwordEncoder);
    }

    @Bean
    public OAuth2ResourceOwnerPasswordAuthenticationProvider oAuth2ResourceOwnerPasswordAuthenticationProvider() {
        return new OAuth2ResourceOwnerPasswordAuthenticationProvider(userDetailService, passwordEncoder, authorizationService, tokenGenerator);
    }
}
