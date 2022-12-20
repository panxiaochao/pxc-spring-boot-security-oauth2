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
public enum AlgorithmEnum {
    /**
     * 加密类型
     */
    MD5("MD5"), SHA1("SHA-1"), SHA256("SHA-256"), SHA384("SHA-384"), SHA512("SHA-512");

    private String name;
}
