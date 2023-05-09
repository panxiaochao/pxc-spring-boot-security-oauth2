package io.github.panxiaochao.security.properties;

import io.github.panxiaochao.security.crypto.PasswordEncoderEnum;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * {@code OAuth2SelfProperties}
 * <p> description: 自定义属性
 *
 * @author Lypxc
 * @since 2022-12-20
 */
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "spring.security.oauth2.self", ignoreInvalidFields = true)
public class OAuth2SelfProperties implements InitializingBean {
    /**
     * CLIENT_ID
     */
    private String clientId;

    /**
     * CLIENT_SECRET
     */
    private String clientSecret;

    /**
     * CLIENT_SERVER
     */
    private String clientServer;

    /**
     * passwordEncoder 密码加密模式
     */
    private PasswordEncoderEnum passwordEncoder;

    /**
     * accessTokenTimeToLive, default seconds
     */
    private long accessTokenTimeToLive = 3600;

    /**
     * refreshTokenTimeToLive, default seconds
     */
    private long refreshTokenTimeToLive = 7200;

    /**
     * seed
     */
    private String seed = "pxc-oauth2-seed";


    @Override
    public void afterPropertiesSet() throws Exception {
    }
}
