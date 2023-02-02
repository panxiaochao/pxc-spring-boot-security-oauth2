package io.github.panxiaochao.security.core.token;

import io.github.panxiaochao.security.constant.GlobalSecurityConstants;
import org.springframework.lang.Nullable;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * {@code OAuth2CustomizeAccessTokenGenerator}
 * <p> description: 自定义生成Token, 加入自己的参数
 *
 * @author Lypxc
 * @since 2022-12-21
 */
public class OAuth2CustomizeAccessTokenGenerator implements OAuth2TokenGenerator<Jwt> {

    private final StringKeyGenerator accessTokenGenerator =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    /**
     * Customizer JwtEncoder
     */
    private final JwtEncoder jwtEncoder;

    public OAuth2CustomizeAccessTokenGenerator(JwtEncoder jwtEncoder) {
        Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
        this.jwtEncoder = jwtEncoder;
    }

    @Nullable
    @Override
    public Jwt generate(OAuth2TokenContext context) {
        // TOKEN_TYPE: CUSTOMIZE_ACCESS_TOKEN
        if (context.getTokenType() == null ||
                (!GlobalSecurityConstants.CUSTOMIZE_ACCESS_TOKEN.equals(context.getTokenType()) &&
                        !OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue()))) {
            return null;
        }
        if (GlobalSecurityConstants.CUSTOMIZE_ACCESS_TOKEN.equals(context.getTokenType()) &&
                !OAuth2TokenFormat.SELF_CONTAINED.equals(context.getRegisteredClient().getTokenSettings().getAccessTokenFormat())) {
            return null;
        }

        String issuer = null;
        if (context.getAuthorizationServerContext() != null) {
            issuer = context.getAuthorizationServerContext().getIssuer();
        }
        RegisteredClient registeredClient = context.getRegisteredClient();
        // China UTC+8 Instant
        Instant issuedAt = Instant.now();
        Instant expiresAt;
        JwsAlgorithm jwsAlgorithm = SignatureAlgorithm.RS256;
        if (registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm() != null) {
            jwsAlgorithm = registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm();
        }
        if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
            expiresAt = issuedAt.plus(30, ChronoUnit.MINUTES);
        } else {
            expiresAt = issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());
        }

        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();
        if (StringUtils.hasText(issuer)) {
            claimsBuilder.issuer(issuer);
        }
        Map<String, Object> claimsMap = new HashMap<>();
        claimsBuilder
                .subject(context.getPrincipal().getName())
                .audience(Collections.singletonList(registeredClient.getClientId()))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .notBefore(issuedAt)
                .id(UUID.randomUUID().toString());
        if (GlobalSecurityConstants.CUSTOMIZE_ACCESS_TOKEN.equals(context.getTokenType())) {
            if (!CollectionUtils.isEmpty(context.getAuthorizedScopes())) {
                claimsBuilder.claim(OAuth2ParameterNames.SCOPE, context.getAuthorizedScopes());
            }
        } else if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
            claimsBuilder.claim(IdTokenClaimNames.AZP, registeredClient.getClientId());
        }

        JwsHeader.Builder jwsHeaderBuilder = JwsHeader.with(jwsAlgorithm);

        // 以下是自定义数据，直接增强用户数据
        // 去除 this.jwtCustomizer 代码，主要是因为本身类已重写，没有必要再去另外写一个
        // 之前是因为Spring已封装，所以需要拓展增强JWT里面的数据
        claimsBuilder.claims(claims -> claims.put("pxc", "数据增强"));

        JwsHeader jwsHeader = jwsHeaderBuilder.build();
        JwtClaimsSet claims = claimsBuilder.build();
        return this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));
    }
}
