package io.github.panxiaochao.web.sys.user.service;

import com.baomidou.mybatisplus.extension.service.IService;
import io.github.panxiaochao.web.sys.user.entity.SysUser;

/**
 * <p>
 * 用户表 服务类
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
public interface ISysUserService extends IService<SysUser> {

    /**
     * 根据用户名查找用户
     *
     * @param username
     * @return
     */
    SysUser findUserByUsername(String username);

    /**
     * 根据自定义模式IdentityType验证
     *
     * @param username
     * @param credentialsType
     * @return
     */
    SysUser findUserByIdentityType(String username, String credentialsType);

}
