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

    private static final String ALGORITHM_HMAC_SHA_1 = "HmacSHA1";
    private static final String ALGORITHM_HMAC_SHA_256 = "HmacSHA256";

    private static final int KEY_SIZE = 2048;

    private KeyGeneratorUtils() {
    }

    public static SecretKey generateSecretKey() {
        SecretKey hmacKey;
        try {
            hmacKey = KeyGenerator.getInstance(ALGORITHM_HMAC_SHA_256).generateKey();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return hmacKey;
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
                keyPairGenerator.initialize(KEY_SIZE, secureRandom);
            } else {
                keyPairGenerator.initialize(KEY_SIZE);
            }
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}
