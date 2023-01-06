package io.github.panxiaochao.security.core.token;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * {@code OAuth2CustomizeAccessToken}
 * <p> description: 自定义Token
 *
 * @author Lypxc
 * @since 2022-12-21
 */
@Getter
@Setter
public class OAuth2CustomizeAccessToken extends OAuth2AccessToken {

    private final Map<String, Object> claims;

    public OAuth2CustomizeAccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt, Map<String, Object> claims) {
        super(tokenType, tokenValue, issuedAt, expiresAt, Collections.emptySet());
        this.claims = claims;
    }

    public OAuth2CustomizeAccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt, Set<String> scopes, Map<String, Object> claims) {
        super(tokenType, tokenValue, issuedAt, expiresAt, scopes);
        this.claims = claims;
    }
}
