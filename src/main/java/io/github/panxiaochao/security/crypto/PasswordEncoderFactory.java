package io.github.panxiaochao.security.crypto;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Lypxc
 */
public class PasswordEncoderFactory {

    public static final String PWD_ENCODER_BCRYPT = "bcrypt";
    public static final String PWD_ENCODER_SCRYPT = "scrypt";
    public static final String PWD_ENCODER_PBKDF2 = "pbkdf2";
    public static final String PWD_CUSTOM_ENCODER_MD5 = "MD5";

    public static final String PWD_ENCODER_SHA_1 = "SHA-1";
    public static final String PWD_ENCODER_SHA_256 = "SHA-256";
    public static final String PWD_ENCODER_SHA_384 = "SHA-384";
    public static final String PWD_ENCODER_SHA_512 = "SHA-512";

    public static final String PWD_ENCODER_SHA256 = "sha256";

    /*
     * 当前版本5新增支持加密方式： bcrypt - BCryptPasswordEncoder (Also used for encoding)
     * ldap - LdapShaPasswordEncoder MD4 - Md4PasswordEncoder MD5 - new
     * MessageDigestPasswordEncoder("MD5") noop - NoOpPasswordEncoder pbkdf2 -
     * Pbkdf2PasswordEncoder scrypt - SCryptPasswordEncoder SHA-1 - new
     * MessageDigestPasswordEncoder("SHA-1") SHA-256 - new
     * MessageDigestPasswordEncoder("SHA-256") sha256 - StandardPasswordEncoder
     */

    private static final Map<String, PasswordEncoder> PASSWORD_ENCODERS = new HashMap<>();

    static {
        PASSWORD_ENCODERS.put(PWD_ENCODER_BCRYPT, new BCryptPasswordEncoder());
        PASSWORD_ENCODERS.put(PWD_ENCODER_SCRYPT, new SCryptPasswordEncoder());
        PASSWORD_ENCODERS.put(PWD_ENCODER_PBKDF2, new Pbkdf2PasswordEncoder());
        PASSWORD_ENCODERS.put(PWD_CUSTOM_ENCODER_MD5,
                new CusMessageDigestPasswordEncoder(AlgorithmEnum.MD5.getName()));
        PASSWORD_ENCODERS.put(PWD_ENCODER_SHA_1,
                new CusMessageDigestPasswordEncoder(AlgorithmEnum.SHA1.getName()));
        PASSWORD_ENCODERS.put(PWD_ENCODER_SHA_256,
                new CusMessageDigestPasswordEncoder(AlgorithmEnum.SHA256.getName()));
        PASSWORD_ENCODERS.put(PWD_ENCODER_SHA_384,
                new CusMessageDigestPasswordEncoder(AlgorithmEnum.SHA384.getName()));
        PASSWORD_ENCODERS.put(PWD_ENCODER_SHA_512,
                new CusMessageDigestPasswordEncoder(AlgorithmEnum.SHA512.getName()));
    }

    private PasswordEncoderFactory() {
    }

    /**
     * 获取加密的实例
     *
     * @param encoderId 加密方式
     * @return PasswordEncoder
     */
    public static PasswordEncoder getInstance(String encoderId) {
        return new DelegatingPasswordEncoder(encoderId, PASSWORD_ENCODERS);
    }
}
