package io.github.panxiaochao.security.utils;

import org.springframework.util.StringUtils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

/**
 * {@code KeyGeneratorUtils}
 * <p> description: 密钥生成工具
 *
 * @author Lypxc
 * @since 2022-12-14
 */
public class KeyGeneratorUtils {

    private static final String ALGORITHM_RSA = "RSA";

    public static final String ALGORITHM_HMAC_SHA_1 = "HmacSHA1";

    public static final String ALGORITHM_HMAC_SHA_256 = "HmacSHA256";

    public static final int DEFAULT_KEY_SIZE = 2048;

    private KeyGeneratorUtils() {
    }

    public static SecretKey generateSecretKey() {
        try {
            return KeyGenerator.getInstance(ALGORITHM_HMAC_SHA_256).generateKey();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    public static SecretKey generateSecretKey(String algorithm) {
        try {
            if (StringUtils.hasText(algorithm)) {
                return KeyGenerator.getInstance(algorithm).generateKey();
            }
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return null;
    }

    public static KeyPair generateRsaKey() {
        return generateRsaKey(null);
    }

    public static KeyPair generateRsaKey(String seed) {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_RSA);
            if (StringUtils.hasText(seed)) {
                SecureRandom secureRandom = new SecureRandom(seed.getBytes());
                keyPairGenerator.initialize(DEFAULT_KEY_SIZE, secureRandom);
            } else {
                keyPairGenerator.initialize(DEFAULT_KEY_SIZE);
            }
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}
