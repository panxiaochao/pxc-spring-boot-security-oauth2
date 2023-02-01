package io.github.panxiaochao.security.crypto;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.*;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Lypxc
 */
public class PasswordEncoderFactory {

    private static final Map<String, PasswordEncoder> ENCODERS = new HashMap<>();


    static {
        ENCODERS.put(PasswordEncoderEnum.LDAP.getName(), new LdapShaPasswordEncoder());
        ENCODERS.put(PasswordEncoderEnum.NOOP.getName(), NoOpPasswordEncoder.getInstance());
        ENCODERS.put(PasswordEncoderEnum.BCRYPT.getName(), new BCryptPasswordEncoder());
        ENCODERS.put(PasswordEncoderEnum.SCRYPT.getName(), new SCryptPasswordEncoder());
        ENCODERS.put(PasswordEncoderEnum.PBKDF2.getName(), new Pbkdf2PasswordEncoder());
        ENCODERS.put(PasswordEncoderEnum.MD4.getName(), new Md4PasswordEncoder());
        ENCODERS.put(PasswordEncoderEnum.MD5.getName(),
                new MessageDigestPasswordEncoder(PasswordEncoderEnum.MD5.getName()));
        ENCODERS.put(PasswordEncoderEnum.SHA_1.getName(),
                new MessageDigestPasswordEncoder(PasswordEncoderEnum.SHA_1.getName()));
        ENCODERS.put(PasswordEncoderEnum.SHA_256.getName(),
                new MessageDigestPasswordEncoder(PasswordEncoderEnum.SHA_256.getName()));
        ENCODERS.put(PasswordEncoderEnum.SHA_384.getName(),
                new MessageDigestPasswordEncoder(PasswordEncoderEnum.SHA_384.getName()));
        ENCODERS.put(PasswordEncoderEnum.SHA_512.getName(),
                new MessageDigestPasswordEncoder(PasswordEncoderEnum.SHA_512.getName()));
        ENCODERS.put(PasswordEncoderEnum.SHA256.getName(), new StandardPasswordEncoder());
        ENCODERS.put(PasswordEncoderEnum.ARGON2.getName(), new Argon2PasswordEncoder());
    }

    /**
     * Creates a {@link DelegatingPasswordEncoder} with default mappings. Additional
     * mappings may be added and the encoding will be updated to conform with best
     * practices. However, due to the nature of {@link DelegatingPasswordEncoder} the
     * updates should not impact users. The mappings current are:
     *
     * <ul>
     * <li>bcrypt - {@link BCryptPasswordEncoder} (Also used for encoding)</li>
     * <li>ldap -
     * {@link org.springframework.security.crypto.password.LdapShaPasswordEncoder}</li>
     * <li>MD4 -
     * {@link org.springframework.security.crypto.password.Md4PasswordEncoder}</li>
     * <li>MD5 - {@code new MessageDigestPasswordEncoder("MD5")}</li>
     * <li>noop -
     * {@link org.springframework.security.crypto.password.NoOpPasswordEncoder}</li>
     * <li>pbkdf2 - {@link Pbkdf2PasswordEncoder}</li>
     * <li>scrypt - {@link SCryptPasswordEncoder}</li>
     * <li>SHA-1 - {@code new MessageDigestPasswordEncoder("SHA-1")}</li>
     * <li>SHA-256 - {@code new MessageDigestPasswordEncoder("SHA-256")}</li>
     * <li>sha256 -
     * {@link org.springframework.security.crypto.password.StandardPasswordEncoder}</li>
     * <li>argon2 - {@link Argon2PasswordEncoder}</li>
     * </ul>
     *
     * @return the {@link PasswordEncoder} to use
     */
    public static PasswordEncoder createDelegatingPasswordEncoder() {
        return new DelegatingPasswordEncoder(PasswordEncoderEnum.MD5.getName(), ENCODERS);
    }

    /**
     * 获取加密的实例
     *
     * @param encoderId 加密方式
     * @return PasswordEncoder
     */
    public static PasswordEncoder createDelegatingPasswordEncoder(String encoderId) {
        return new DelegatingPasswordEncoder(encoderId, ENCODERS);
    }
}
