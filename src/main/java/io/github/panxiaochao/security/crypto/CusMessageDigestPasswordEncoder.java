package io.github.panxiaochao.security.crypto;

import io.github.panxiaochao.jwt.utils.cypto.MessageDigestGenerator;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * {@code CusMessageDigestPasswordEncoder}
 * <p> 自定义加密方式, 支持MD5, SHA-1, SHA-256, SHA-384, SHA-512
 *
 * @author Lypxc
 * @since 2022/4/18
 */
public class CusMessageDigestPasswordEncoder implements PasswordEncoder {
    private final MessageDigestGenerator messageDigestGenerator;

    public CusMessageDigestPasswordEncoder(String algorithm) {
        this.messageDigestGenerator = new MessageDigestGenerator(algorithm);
    }

    public void setEncodeHashAsBase64(boolean encodeHashAsBase64) {
        messageDigestGenerator.setEncodeHashAsBase64(encodeHashAsBase64);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return messageDigestGenerator.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return messageDigestGenerator.matches(rawPassword, encodedPassword);
    }

    public static void main(String[] args) {
        CusMessageDigestPasswordEncoder md5PasswordEncoder = new CusMessageDigestPasswordEncoder(AlgorithmEnum.MD5.getName());
        // md5PasswordEncoder.setEncodeHashAsBase64(true);
        // System.out.println(md5PasswordEncoder.encode("client1"));
        System.out.println(md5PasswordEncoder.matches("client1", "{YD1hGtvB9GGyv5DB338bXR5Jf1OnTA81sT+ckyI3PRE=}8a56ee5ed9c96941d75ff36c7323ba0a"));
    }
}
