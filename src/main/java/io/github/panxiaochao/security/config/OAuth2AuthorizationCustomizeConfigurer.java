package io.github.panxiaochao.security.config;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

/**
 * {@code AuthenticationConverterConfig}
 * <p> description: An
 *
 * @author Lypxc
 * @since 2022-12-19
 */
public final class OAuth2AuthorizationCustomizeConfigurer extends AbstractHttpConfigurer<OAuth2AuthorizationCustomizeConfigurer, HttpSecurity> {

    private static final Logger LOGGER = LogManager.getLogger(OAuth2AuthorizationCustomizeConfigurer.class);

    // @Override
    // public void configure(HttpSecurity httpSecurity) {
    //     httpSecurity.authenticationProvider()
    // }


    // @Bean
    // public AuthenticationConverter authenticationConverter() {
    //     LOGGER.info(">>> 自定义AuthenticationConverter配置");
    //     final List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
    //     return (request) -> {
    //         Assert.notNull(request, "request cannot be null");
    //         for (AuthenticationConverter converter : authenticationConverters) {
    //             Authentication authentication = converter.convert(request);
    //             if (authentication != null) {
    //                 return authentication;
    //             ;
    //         }
    //         return null;
    //     };
    // }

    // @Bean
    // public DelegatingAuthenticationConverter delegatingAuthenticationConverter() {
    //     return new DelegatingAuthenticationConverter(createDefaultAuthenticationConverters());
    // }
    //
    // private static List<AuthenticationConverter> createDefaultAuthenticationConverters() {
    //     List<AuthenticationConverter> authenticationConverters = new ArrayList<>();
    //     authenticationConverters.add(new OAuth2AuthorizationCodeAuthenticationConverter());
    //     authenticationConverters.add(new OAuth2RefreshTokenAuthenticationConverter());
    //     authenticationConverters.add(new OAuth2ClientCredentialsAuthenticationConverter());
    //     // custom password converter
    //     authenticationConverters.add(new OAuth2ResourceOwnerPasswordAuthenticationConverter());
    //     return authenticationConverters;
    // }

}
