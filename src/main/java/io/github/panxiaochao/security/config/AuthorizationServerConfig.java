package io.github.panxiaochao.security.config;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.github.panxiaochao.security.constant.GlobalSecurityConstants;
import io.github.panxiaochao.security.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationConverter;
import io.github.panxiaochao.security.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationProvider;
import io.github.panxiaochao.security.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationToken;
import io.github.panxiaochao.security.core.token.OAuth2CustomizeAccessTokenGenerator;
import io.github.panxiaochao.security.handler.CustomAccessDeniedHandler;
import io.github.panxiaochao.security.handler.CustomAuthenticationFailureHandler;
import io.github.panxiaochao.security.jackson2.mixin.OAuth2ResourceOwnerPasswordMixin;
import io.github.panxiaochao.security.properties.OAuth2SelfProperties;
import io.github.panxiaochao.security.service.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.annotation.Resource;
import javax.sql.DataSource;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * {@code AuthorizationServerConfig}
 * <p>
 *
 * @author Lypxc
 * @since 2022-09-04
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationServerConfig.class);

    @Resource
    private OAuth2SelfProperties selfProperties;

    @Resource
    private PasswordEncoder passwordEncoder;

    @Resource
    private UserDetailsServiceImpl userDetailService;

    @Resource
    public JWKSource<SecurityContext> jwkSource;

    @Resource
    private OAuth2AuthorizationService authorizationService;

    @Bean
    public JdbcTemplate jdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }

    /**
     * ????????????????????? OAuth2 ?????????????????????????????????????????????????????????
     *
     * @return AuthorizationServerSettings
     * @since 0.4.0
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        LOGGER.info(">>> ????????? AuthorizationServerSettings ??????");
        return AuthorizationServerSettings.builder()
                // .authorizationEndpoint("/oauth2/v1/authorize")
                .tokenEndpoint(GlobalSecurityConstants.TOKEN_ENDPOINT)
                .tokenIntrospectionEndpoint("/oauth2/v1/introspect")
                .tokenRevocationEndpoint("/oauth2/v1/revoke")
                .jwkSetEndpoint("/oauth2/v1/jwks")
                .oidcUserInfoEndpoint("/connect/v1/userinfo")
                .oidcClientRegistrationEndpoint("/connect/v1/register")
                // .issuer("http://127.0.0.1:18000/")
                .build();
    }

    /**
     * A Spring Security filter chain for the Protocol Endpoints.
     *
     * @param http HttpSecurity
     * @return SecurityFilterChain
     * @throws Exception ??????
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        LOGGER.info(">>> ????????? AuthorizationServerSecurityFilterChain ??????");
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        //
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        http.requestMatcher(endpointsMatcher)
                .authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                // ??????????????????
                .exceptionHandling(exception -> {
                    exception
                            .accessDeniedHandler(new CustomAccessDeniedHandler())
                            // .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
                            // ???????????????????????????
                            .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
                })
                .apply(authorizationServerConfigurer);
        // custom converter and provider and tokenGenerator
        OAuth2TokenGenerator<? extends OAuth2Token> customizerTokenGenerator = tokenGenerator();
        authorizationServerConfigurer.tokenGenerator(customizerTokenGenerator);
        authorizationServerConfigurer.tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint
                                .accessTokenRequestConverter(new OAuth2ResourceOwnerPasswordAuthenticationConverter())
                                // ?????????????????????
                                .errorResponseHandler(new CustomAuthenticationFailureHandler())
                )
                // ???????????????
                .clientAuthentication(clientAuthentication ->
                        clientAuthentication
                                .authenticationProviders(authenticationProviders ->
                                        customizerGrantAuthenticationProviders(authenticationProviders, customizerTokenGenerator))
                                // ?????????????????????
                                .errorResponseHandler(new CustomAuthenticationFailureHandler())
                );
        return http.build();
    }

    /**
     * ???????????????????????????
     * <p>
     * 1.????????????
     */
    private void customizerGrantAuthenticationProviders(List<AuthenticationProvider> authenticationProviders, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        LOGGER.info(">>> ????????? addCustomOAuth2GrantAuthenticationProvider ??????");

        OAuth2ResourceOwnerPasswordAuthenticationProvider resourceOwnerPasswordAuthenticationProvider =
                new OAuth2ResourceOwnerPasswordAuthenticationProvider(userDetailService, passwordEncoder, authorizationService, tokenGenerator);

        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        daoAuthenticationProvider.setUserDetailsService(userDetailService);

        // ????????????
        authenticationProviders.add(resourceOwnerPasswordAuthenticationProvider);
        // ?????????Dao??????
        authenticationProviders.add(daoAuthenticationProvider);
    }

    /**
     * ???????????????Token??????
     *
     * @return OAuth2TokenGenerator
     */
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {
        LOGGER.info(">>> ????????? OAuth2TokenGenerator ??????");
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        OAuth2CustomizeAccessTokenGenerator customizeAccessTokenGenerator = new OAuth2CustomizeAccessTokenGenerator(jwtEncoder);
        // ?????????????????????????????????????????????????????????
        return new DelegatingOAuth2TokenGenerator(customizeAccessTokenGenerator, jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    /**
     * ??????????????????????????? Client ??????
     *
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        LOGGER.info(">>> ????????? RegisteredClientRepository ??????");
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        // ??????????????????clientId
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(selfProperties.getClientId());
        if (Objects.isNull(registeredClient)) {
            registeredClient = createRegisteredClient();
            registeredClientRepository.save(registeredClient);
        }
        // AUTHORIZATION_CODE
        registeredClient = registeredClientRepository.findByClientId("client_code");
        if (Objects.isNull(registeredClient)) {
            registeredClient = createAuthorizationCodeRegisteredClient();
            registeredClientRepository.save(registeredClient);
        }
        return registeredClientRepository;
    }

    /**
     * ???????????????????????????
     *
     * @return
     */
    private RegisteredClient createRegisteredClient() {
        return RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId(selfProperties.getClientId())
                .clientSecret(passwordEncoder.encode(selfProperties.getClientSecret()))
                .clientName(selfProperties.getClientServer())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .tokenSettings(tokenSettings())
                .clientSettings(clientSettings(false))
                .build();
    }

    /**
     * <p>
     * http://127.0.0.1:18000/oauth2/authorize?response_type=code&client_id=client_code&scope=message.read&redirect_uri=https://www.baidu.com
     *
     * @return RegisteredClient
     */
    private RegisteredClient createAuthorizationCodeRegisteredClient() {
        return RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("client_code")
                .clientSecret(passwordEncoder.encode("123456@"))
                .clientName("client_code_server")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // ????????????
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .redirectUri("https://www.baidu.com")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("message.read")
                .scope("message.write")
                .tokenSettings(tokenSettings())
                .clientSettings(clientSettings(true))
                .build();
    }

    /**
     * ?????????????????????????????????????????????
     *
     * @param jdbcTemplate               ?????????
     * @param registeredClientRepository ?????????????????????
     * @return OAuth2AuthorizationService
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        JdbcOAuth2AuthorizationService authorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper authorizationRowMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository);
        ObjectMapper objectMapper = new ObjectMapper();
        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        objectMapper.registerModules(securityModules);
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        // You will need to write the Mixin for your class so Jackson can marshall it.
        objectMapper.addMixIn(OAuth2ResourceOwnerPasswordAuthenticationToken.class, OAuth2ResourceOwnerPasswordMixin.class);
        authorizationRowMapper.setObjectMapper(objectMapper);
        authorizationRowMapper.setLobHandler(new DefaultLobHandler());
        authorizationService.setAuthorizationRowMapper(authorizationRowMapper);
        return authorizationService;
    }

    /**
     * ????????????????????????????????????
     *
     * @param jdbcTemplate               ?????????
     * @param registeredClientRepository ?????????????????????
     * @return OAuth2AuthorizationConsentService
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * JWT???Json Web Token??????????????????TTL???????????????refreshToken??????
     *
     * @return TokenSettings
     */
    public TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .reuseRefreshTokens(true)
                .accessTokenTimeToLive(Duration.ofSeconds(selfProperties.getAccessTokenTimeToLive()))
                .refreshTokenTimeToLive(Duration.ofSeconds(selfProperties.getRefreshTokenTimeToLive()))
                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS512)
                .build();
    }


    /**
     * ?????????????????????
     *
     * @return ClientSettings
     */
    public ClientSettings clientSettings(boolean requireAuthorizationConsent) {
        return ClientSettings.builder()
                // ??????????????????????????????
                .requireAuthorizationConsent(requireAuthorizationConsent)
                .build();
    }
}
