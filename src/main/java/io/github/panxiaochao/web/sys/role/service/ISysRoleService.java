package io.github.panxiaochao.web.sys.role.service;

import com.baomidou.mybatisplus.extension.service.IService;
import io.github.panxiaochao.web.sys.role.entity.SysRole;
import io.github.panxiaochao.web.sys.user.entity.SysUser;

import java.util.List;

/**
 * <p>
 * 角色表 服务类
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
public interface ISysRoleService extends IService<SysRole> {
    /**
     * 查找用户的所有角色
     *
     * @param sysUser
     * @return
     */
    List<SysRole> queryRolesByUser(SysUser sysUser);
}
