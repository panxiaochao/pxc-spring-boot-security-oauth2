package io.github.panxiaochao.security.crypto;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * {@code PasswordEncoderEnum}
 * <p> description:
 *
 * @author Lypxc
 * @since 2022-12-20
 */
@Getter
@AllArgsConstructor
public enum PasswordEncoderEnum {
    /**
     * 加密类型
     */
    LDAP("ldap"),
    NOOP("noop"),
    BCRYPT("bcrypt"),
    ARGON2("argon2"),
    SCRYPT("scrypt"),
    PBKDF2("pbkdf2"),
    MD4("MD4"),
    MD5("MD5"),
    SHA_1("SHA-1"),
    SHA_256("SHA-256"),
    SHA_384("SHA-384"),
    SHA_512("SHA-512"),
    SHA256("Ssha256");

    private final String name;
}
