package io.github.panxiaochao.security.core.endpoint;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

/**
 * {@code CusOAuth2ParameterNames}
 * <p>
 * Standard and custom (non-standard) parameter names defined in the OAuth Parameters
 * Registry and used by the authorization endpoint, token endpoint and token revocation
 * endpoint.
 *
 * @author Lypxc
 * @since 2022-12-16
 */
public interface CusOAuth2ParameterNames extends OAuth2ParameterNames {

    /**
     * {@code identity_type} - used in Access Token Request.
     */
    String IDENTITY_TYPE = "identity_type";
}
