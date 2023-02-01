// package io.github.panxiaochao.security.core.customizer;
//
// import org.slf4j.Logger;
// import org.slf4j.LoggerFactory;
// import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
// import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
// import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
//
// /**
//  * {@code OAuth2ResourceOwnerPasswordAccessTokenCustomizer}
//  * <p> description: ResourceOwnerPassword Gant AccessToken Customizer
//  *
//  * @author Lypxc
//  * @since 2023-01-31
//  */
// public class OAuth2ResourceOwnerPasswordAccessTokenCustomizer implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {
//
//     private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2ResourceOwnerPasswordAccessTokenCustomizer.class);
//
//     /**
//      * Customize the OAuth 2.0 Token attributes.
//      *
//      * @param context the context containing the OAuth 2.0 Token attributes
//      */
//     @Override
//     public void customize(OAuth2TokenClaimsContext context) {
//         OAuth2TokenClaimsSet.Builder claims = context.getClaims();
//         // Customize claims
//         LOGGER.info("accessTokenCustomizer claims");
//     }
// }
