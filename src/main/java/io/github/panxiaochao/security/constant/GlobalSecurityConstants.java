package io.github.panxiaochao.security.constant;

import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

/**
 * @author Lypxc
 * @version 1.0
 * @since 2021年6月22日
 */
public final class GlobalSecurityConstants {

    private GlobalSecurityConstants() {
    }

    public static final String TOKEN_ENDPOINT = "/oauth2/v1/token";

    public static final OAuth2TokenType CUSTOMIZE_ACCESS_TOKEN = new OAuth2TokenType("customize_access_token");
}
