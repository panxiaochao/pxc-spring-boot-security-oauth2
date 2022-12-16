package io.github.panxiaochao.web.sys.user.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * <p>
 * 用户授权信息表
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
public class SysUserAuths implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 唯一标识
     */
    @TableId(value = "id", type = IdType.AUTO)
    private Integer id;

    /**
     * 关联用户ID
     */
    private Integer userId;

    /**
     * 登录类型(手机号/邮箱/用户名/微信/微博/QQ）等
     */
    private String identityType;

    /**
     * 登录标识(手机号/邮箱/用户名/微信/微博/QQ）等唯一标识，等同于登录账号
     */
    private String identifier;

    /**
     * 密码凭证（自建密码，或者第三方access_token）
     */
    private String credential;

    /**
     * 是否已经验证：1验证，0未验证
     */
    private String verified;

    /**
     * 登录标识失效时间
     */
    private LocalDateTime expireTime;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    public String getIdentityType() {
        return identityType;
    }

    public void setIdentityType(String identityType) {
        this.identityType = identityType;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getCredential() {
        return credential;
    }

    public void setCredential(String credential) {
        this.credential = credential;
    }

    public String getVerified() {
        return verified;
    }

    public void setVerified(String verified) {
        this.verified = verified;
    }

    public LocalDateTime getExpireTime() {
        return expireTime;
    }

    public void setExpireTime(LocalDateTime expireTime) {
        this.expireTime = expireTime;
    }

    @Override
    public String toString() {
        return "SysUserAuths{" +
                "id=" + id +
                ", userId=" + userId +
                ", identityType=" + identityType +
                ", identifier=" + identifier +
                ", credential=" + credential +
                ", verified=" + verified +
                ", expireTime=" + expireTime +
                "}";
    }
}
