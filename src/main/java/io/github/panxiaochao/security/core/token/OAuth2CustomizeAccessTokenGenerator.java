package io.github.panxiaochao.security.core.token;

import io.github.panxiaochao.security.constant.GlobalSecurityConstants;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.UUID;

/**
 * {@code OAuth2CustomizeAccessTokenGenerator}
 * <p> description: 自定义生成Token, 加入自己的参数
 *
 * @author Lypxc
 * @since 2022-12-21
 */
public class OAuth2CustomizeAccessTokenGenerator implements OAuth2TokenGenerator<OAuth2CustomizeAccessToken> {

    private final StringKeyGenerator accessTokenGenerator =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    private OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer;

    @Override
    public OAuth2CustomizeAccessToken generate(OAuth2TokenContext context) {
        // CUSTOMIZE_ACCESS_TOKEN
        // TODO: 2022/12/22 token少了
        if (!GlobalSecurityConstants.CUSTOMIZE_ACCESS_TOKEN.equals(context.getTokenType())) {
            return null;
        }
        String issuer = null;
        if (context.getAuthorizationServerContext() != null) {
            issuer = context.getAuthorizationServerContext().getIssuer();
        }
        RegisteredClient registeredClient = context.getRegisteredClient();

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());

        OAuth2TokenClaimsSet.Builder claimsBuilder = OAuth2TokenClaimsSet.builder();
        if (StringUtils.hasText(issuer)) {
            claimsBuilder.issuer(issuer);
        }
        claimsBuilder
                .subject(context.getPrincipal().getName())
                .audience(Collections.singletonList(registeredClient.getClientId()))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .notBefore(issuedAt)
                .id(UUID.randomUUID().toString());
        if (!CollectionUtils.isEmpty(context.getAuthorizedScopes())) {
            claimsBuilder.claim(OAuth2ParameterNames.SCOPE, context.getAuthorizedScopes());
        }
        if (this.accessTokenCustomizer != null) {
            OAuth2TokenClaimsContext.Builder accessTokenContextBuilder = OAuth2TokenClaimsContext.with(claimsBuilder)
                    .registeredClient(context.getRegisteredClient())
                    .principal(context.getPrincipal())
                    .authorizationServerContext(context.getAuthorizationServerContext())
                    .authorizedScopes(context.getAuthorizedScopes())
                    .tokenType(context.getTokenType())
                    .authorizationGrantType(context.getAuthorizationGrantType());
            if (context.getAuthorization() != null) {
                accessTokenContextBuilder.authorization(context.getAuthorization());
            }
            if (context.getAuthorizationGrant() != null) {
                accessTokenContextBuilder.authorizationGrant(context.getAuthorizationGrant());
            }
            OAuth2TokenClaimsContext accessTokenContext = accessTokenContextBuilder.build();
            this.accessTokenCustomizer.customize(accessTokenContext);
        }
        OAuth2TokenClaimsSet accessTokenClaimsSet = claimsBuilder.build();
        OAuth2CustomizeAccessToken accessToken = new OAuth2CustomizeAccessToken(OAuth2AccessToken.TokenType.BEARER,
                this.accessTokenGenerator.generateKey(), accessTokenClaimsSet.getIssuedAt(), accessTokenClaimsSet.getExpiresAt(),
                context.getAuthorizedScopes(), accessTokenClaimsSet.getClaims());
        return accessToken;
    }

    public void setAccessTokenCustomizer(OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer) {
        Assert.notNull(accessTokenCustomizer, "accessTokenCustomizer cannot be null");
        this.accessTokenCustomizer = accessTokenCustomizer;
    }
}
