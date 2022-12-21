package io.github.panxiaochao.security.config;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.github.panxiaochao.security.constant.SecurityConstants;
import io.github.panxiaochao.security.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationConverter;
import io.github.panxiaochao.security.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationProvider;
import io.github.panxiaochao.security.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationToken;
import io.github.panxiaochao.security.handler.CustomAccessDeniedHandler;
import io.github.panxiaochao.security.jackson2.mixin.OAuth2ResourceOwnerPasswordMixin;
import io.github.panxiaochao.security.properties.OAuth2SelfProperties;
import io.github.panxiaochao.security.utils.KeyGeneratorUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
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
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * {@code AuthorizationServerConfig}
 * <p>
 *
 * @author Mr_LyPxc
 * @since 2022-09-04
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
    private static final Logger LOGGER = LogManager.getLogger(AuthorizationServerConfig.class);

    @Resource
    private OAuth2SelfProperties selfProperties;

    @Resource
    private PasswordEncoder passwordEncoder;

    @Resource
    private OAuth2ResourceOwnerPasswordAuthenticationProvider resourceOwnerPasswordAuthenticationProvider;

    @Resource
    public DaoAuthenticationProvider daoAuthenticationProvider;

    @Bean
    public JdbcTemplate jdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }

    /**
     * （必需）自定义 OAuth2 授权服务器配置设置的，可以自定义请求端
     * since 0.4.0
     *
     * @return AuthorizationServerSettings
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        LOGGER.info(">>> 自定义 AuthorizationServerSettings 配置");
        return AuthorizationServerSettings.builder()
                // .authorizationEndpoint("/oauth2/v1/authorize")
                .tokenEndpoint(SecurityConstants.TOKEN_ENDPOINT)
                .tokenIntrospectionEndpoint("/oauth2/v1/introspect")
                .tokenRevocationEndpoint("/oauth2/v1/revoke")
                .jwkSetEndpoint("/oauth2/v1/jwks")
                .oidcUserInfoEndpoint("/connect/v1/userinfo")
                .oidcClientRegistrationEndpoint("/connect/v1/register")
                .issuer("http://127.0.0.1:18000/")
                .build();
    }

    /**
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        LOGGER.info(">>> 自定义 AuthorizationServerSecurityFilterChain 配置");
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        // custom converter and provider
        authorizationServerConfigurer.tokenEndpoint(tokenEndpoint ->
                tokenEndpoint
                        .accessTokenRequestConverter(new OAuth2ResourceOwnerPasswordAuthenticationConverter())
                        .authenticationProvider(resourceOwnerPasswordAuthenticationProvider)
                        .authenticationProvider(daoAuthenticationProvider));
        //
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        http.requestMatcher(endpointsMatcher)
                .authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationServerConfigurer);
        // 授权异常处理
        http.exceptionHandling(exception -> {
            exception
                    .accessDeniedHandler(new CustomAccessDeniedHandler())
                    // .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
                    .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
        });
        return http.build();
    }

    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(JwtEncoder jwtEncoder) {
        LOGGER.info(">>> 自定义 OAuth2TokenGenerator 配置");
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    /**
     * （必需）负责注册的 Client 信息
     *
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        LOGGER.info(">>> 自定义 RegisteredClientRepository 配置");
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        // 默认查询新建clientId
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
     * 创建客户端秘钥记录
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
     * http://127.0.0.1:18000/oauth2/authorize?response_type=code&client_id=client_code&scope=message.read&redirect_uri=https://www.baidu.com
     *
     * @return
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
                // 回调地址
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
     * 客户端在认证中心的授权信息服务
     *
     * @param jdbcTemplate               数据源
     * @param registeredClientRepository 注册客户端仓库
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
     * 客户端授权的审核信息服务
     *
     * @param jdbcTemplate               数据源
     * @param registeredClientRepository 注册客户端仓库
     * @return OAuth2AuthorizationConsentService
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * @return JWKSource
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = KeyGeneratorUtils.generateRsaKey(selfProperties.getSeed());
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey
                .Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * @param jwkSource
     * @return
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * @param jwkSource
     * @return
     */
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * JWT（Json Web Token）的配置项：TTL、是否复用refreshToken等等
     *
     * @return TokenSettings
     */
    public TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .reuseRefreshTokens(true)
                .accessTokenTimeToLive(Duration.ofSeconds(selfProperties.getAccessTokenTimeToLive()))
                .refreshTokenTimeToLive(Duration.ofSeconds(selfProperties.getRefreshTokenTimeToLive()))
                .build();
    }


    /**
     * 客户端相关配置
     *
     * @return ClientSettings
     */
    public ClientSettings clientSettings(boolean requireAuthorizationConsent) {
        return ClientSettings.builder()
                // 是否需要用户授权确认
                .requireAuthorizationConsent(requireAuthorizationConsent).build();
    }

    // @Bean
    // public OAuth2TokenCustomizer<JwtEncodingContext> buildJwtCustomizer() {
    //
    //     JwtCustomizerHandler jwtCustomizerHandler = JwtCustomizerHandler.getJwtCustomizerHandler();
    //     JwtCustomizer jwtCustomizer = new JwtCustomizerImpl(jwtCustomizerHandler);
    //     OAuth2TokenCustomizer<JwtEncodingContext> customizer = (context) -> {
    //         jwtCustomizer.customizeToken(context);
    //     };
    //
    //     return customizer;
    // }
    //
    // @Bean
    // public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> buildOAuth2TokenClaimsCustomizer() {
    //
    //     OAuth2TokenClaimsCustomizer oauth2TokenClaimsCustomizer = new OAuth2TokenClaimsCustomizerImpl();
    //     OAuth2TokenCustomizer<OAuth2TokenClaimsContext> customizer = (context) -> {
    //         oauth2TokenClaimsCustomizer.customizeTokenClaims(context);
    //     };
    //
    //     return customizer;
    // }

    @Bean
    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer() {
        return context -> {
            OAuth2TokenClaimsSet.Builder claims = context.getClaims();
            // Customize claims
            LOGGER.info("accessTokenCustomizer claims");
        };
    }

    /**
     * 自定义JWT的header和claims
     *
     * @return JWT
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            LOGGER.info("jwtCustomizer claims");
            JwsHeader.Builder headers = context.getJwsHeader();
            JwtClaimsSet.Builder claims = context.getClaims();
            Authentication principal = context.getPrincipal();
            OAuth2Authorization authorization = context.getAuthorization();
            Set<String> authorizedScopes = context.getAuthorizedScopes();
            Authentication authorizationGrant = context.getAuthorizationGrant();
            RegisteredClient registeredClient = context.getRegisteredClient();
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
                // Customize headers/claims for access_token

            } else if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
                // Customize headers/claims for id_token

            } else if (context.getTokenType().getValue().equals(OAuth2TokenType.REFRESH_TOKEN)) {
                // Customize headers/claims for refresh_token

            }
        };
    }
}
