package io.github.panxiaochao.web.sys.role.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import io.github.panxiaochao.web.sys.role.entity.SysRole;
import io.github.panxiaochao.web.sys.user.entity.SysUser;

import java.util.List;

/**
 * <p>
 * 角色表 Mapper 接口
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
public interface SysRoleMapper extends BaseMapper<SysRole> {

    /**
     * 查找用户的所有角色
     *
     * @param sysUser
     * @return
     */
    List<SysRole> queryRolesByUser(SysUser sysUser);
}
