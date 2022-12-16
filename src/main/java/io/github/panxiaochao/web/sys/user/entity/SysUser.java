package io.github.panxiaochao.web.sys.user.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import io.github.panxiaochao.web.sys.role.entity.SysRole;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;

/**
 * <p>
 * 用户表
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
public class SysUser implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 唯一标识
     */
    @TableId(value = "id", type = IdType.AUTO)
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
     * 身份证
     */
    private String idCard;

    /**
     * 用户头像
     */
    private String avatar;

    /**
     * 性别：1男，0女
     */
    private String sex;

    /**
     * 地址
     */
    private String address;

    /**
     * 邮箱
     */
    private String email;

    /**
     * 手机号码
     */
    private String mobile;

    /**
     * 电话号码
     */
    private String tel;

    /**
     * 传真号码
     */
    private String fax;

    /**
     * 排序
     */
    private Integer sort;

    /**
     * 备注
     */
    private String remark;

    /**
     * 人员状态：1正常，0不正常
     */
    private String status;

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
     * 创建时间
     */
    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createTime;

    /**
     * 更新时间
     */
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updateTime;

    /**
     * 登陆次数
     */
    private Integer loginNums;

    /**
     * 登录失败次数
     */
    private Integer loginErrorNums;

    /**
     * 登录时间
     */
    private LocalDateTime loginTime;

    /**
     * 帐号超时期限
     */
    private LocalDateTime expireTime;

    /**
     * 角色集合
     */
    @TableField(exist = false)
    private List<SysRole> roles;

    /**
     * 用户验证类型集合
     */
    @TableField(exist = false)
    private List<SysUserAuths> sysUserAuths;

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

    public String getIdCard() {
        return idCard;
    }

    public void setIdCard(String idCard) {
        this.idCard = idCard;
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

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getMobile() {
        return mobile;
    }

    public void setMobile(String mobile) {
        this.mobile = mobile;
    }

    public String getTel() {
        return tel;
    }

    public void setTel(String tel) {
        this.tel = tel;
    }

    public String getFax() {
        return fax;
    }

    public void setFax(String fax) {
        this.fax = fax;
    }

    public Integer getSort() {
        return sort;
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public String getRemark() {
        return remark;
    }

    public void setRemark(String remark) {
        this.remark = remark;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
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

    public LocalDateTime getCreateTime() {
        return createTime;
    }

    public void setCreateTime(LocalDateTime createTime) {
        this.createTime = createTime;
    }

    public LocalDateTime getUpdateTime() {
        return updateTime;
    }

    public void setUpdateTime(LocalDateTime updateTime) {
        this.updateTime = updateTime;
    }

    public Integer getLoginNums() {
        return loginNums;
    }

    public void setLoginNums(Integer loginNums) {
        this.loginNums = loginNums;
    }

    public Integer getLoginErrorNums() {
        return loginErrorNums;
    }

    public void setLoginErrorNums(Integer loginErrorNums) {
        this.loginErrorNums = loginErrorNums;
    }

    public LocalDateTime getLoginTime() {
        return loginTime;
    }

    public void setLoginTime(LocalDateTime loginTime) {
        this.loginTime = loginTime;
    }

    public LocalDateTime getExpireTime() {
        return expireTime;
    }

    public void setExpireTime(LocalDateTime expireTime) {
        this.expireTime = expireTime;
    }

    public List<SysRole> getRoles() {
        return roles;
    }

    public void setRoles(List<SysRole> roles) {
        this.roles = roles;
    }

    public List<SysUserAuths> getSysUserAuths() {
        return sysUserAuths;
    }

    public void setSysUserAuths(List<SysUserAuths> sysUserAuths) {
        this.sysUserAuths = sysUserAuths;
    }
}
