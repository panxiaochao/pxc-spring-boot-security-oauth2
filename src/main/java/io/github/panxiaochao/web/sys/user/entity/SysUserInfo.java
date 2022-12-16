package io.github.panxiaochao.web.sys.user.entity;

import io.github.panxiaochao.web.sys.role.entity.SysRoleInfo;

import java.util.List;

/**
 * <p>
 * 用户表
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
public class SysUserInfo {
    private Integer id;

    /**
     * 用户真实姓名
     */
    private String realName;

    /**
     * 用户昵称（花名）
     */
    private String nickName;

    /**
     * 用户头像
     */
    private String avatar;

    /**
     * 性别：1男，0女
     */
    private String sex;

    /**
     * 手机号码
     */
    private String mobile;

    /**
     * 皮肤风格
     */
    private String skins;

    /**
     * 所在区域或者部门ID，多数据请用逗号隔开
     */
    private Integer orgId;

    /**
     * 所在区域或者部门编码code，多数据请用逗号隔开
     */
    private String orgCode;

    /**
     * 角色集合
     */
    private List<SysRoleInfo> roles;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getRealName() {
        return realName;
    }

    public void setRealName(String realName) {
        this.realName = realName;
    }

    public String getNickName() {
        return nickName;
    }

    public void setNickName(String nickName) {
        this.nickName = nickName;
    }

    public String getAvatar() {
        return avatar;
    }

    public void setAvatar(String avatar) {
        this.avatar = avatar;
    }

    public String getSex() {
        return sex;
    }

    public void setSex(String sex) {
        this.sex = sex;
    }

    public String getMobile() {
        return mobile;
    }

    public void setMobile(String mobile) {
        this.mobile = mobile;
    }

    public String getSkins() {
        return skins;
    }

    public void setSkins(String skins) {
        this.skins = skins;
    }

    public Integer getOrgId() {
        return orgId;
    }

    public void setOrgId(Integer orgId) {
        this.orgId = orgId;
    }

    public String getOrgCode() {
        return orgCode;
    }

    public void setOrgCode(String orgCode) {
        this.orgCode = orgCode;
    }

    public List<SysRoleInfo> getRoles() {
        return roles;
    }

    public void setRoles(List<SysRoleInfo> roles) {
        this.roles = roles;
    }
}
