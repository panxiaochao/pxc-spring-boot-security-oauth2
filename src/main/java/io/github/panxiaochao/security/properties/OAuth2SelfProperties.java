package io.github.panxiaochao.security.properties;

import io.github.panxiaochao.security.crypto.AlgorithmEnum;
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
     * algorithm
     */
    private String algorithm = AlgorithmEnum.MD5.getName();


    @Override
    public void afterPropertiesSet() throws Exception {
    }
}
