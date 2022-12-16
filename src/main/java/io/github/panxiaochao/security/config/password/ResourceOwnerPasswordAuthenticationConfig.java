package io.github.panxiaochao.security.config.password;

import io.github.panxiaochao.security.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationProvider;
import io.github.panxiaochao.security.service.UserDetailServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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

    @Resource
    private UserDetailServiceImpl userDetailService;

    @Resource
    private PasswordEncoder passwordEncoder;

    @Resource
    private OAuth2AuthorizationService authorizationService;

    @Resource
    private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    @Bean
    public OAuth2ResourceOwnerPasswordAuthenticationProvider resourceOwnerPasswordAuthenticationProvider() {
        return new OAuth2ResourceOwnerPasswordAuthenticationProvider(userDetailService, passwordEncoder, authorizationService, tokenGenerator);
    }
}
