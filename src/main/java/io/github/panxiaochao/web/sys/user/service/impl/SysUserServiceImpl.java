package io.github.panxiaochao.web.sys.user.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import io.github.panxiaochao.web.sys.role.entity.SysRole;
import io.github.panxiaochao.web.sys.role.service.ISysRoleService;
import io.github.panxiaochao.web.sys.user.entity.SysUser;
import io.github.panxiaochao.web.sys.user.entity.SysUserAuths;
import io.github.panxiaochao.web.sys.user.mapper.SysUserMapper;
import io.github.panxiaochao.web.sys.user.service.ISysUserAuthsService;
import io.github.panxiaochao.web.sys.user.service.ISysUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>
 * 用户表 服务实现类
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
@Service
public class SysUserServiceImpl extends ServiceImpl<SysUserMapper, SysUser> implements ISysUserService {

    @Autowired
    private ISysRoleService sysRoleService;

    @Autowired
    private ISysUserAuthsService sysUserAuthsService;

    @Override
    public SysUser findUserByUsername(String username) {
        SysUser sysUser = querySysUserAuthsByIdentity(username, "username");
        if (sysUser != null) {
            List<SysRole> listRoles = sysRoleService.queryRolesByUser(sysUser);
            sysUser.setRoles(listRoles);
            return sysUser;
        }
        return null;
    }

    @Override
    public SysUser findUserByIdentityType(String username, String credentialsType) {
        SysUser sysUser = querySysUserAuthsByIdentity(username, credentialsType);
        if (sysUser != null) {
            List<SysRole> listRoles = sysRoleService.queryRolesByUser(sysUser);
            sysUser.setRoles(listRoles);
            return sysUser;
        }
        return null;
    }

    private SysUser querySysUserAuthsByIdentity(String username, String credentialsType) {
        SysUserAuths sysUserAuths = sysUserAuthsService.querySysUserByIdentity(credentialsType, username);
        if (sysUserAuths == null) {
            return null;
        }
        SysUser sysUser = this.getById(sysUserAuths.getUserId());
        List<SysUserAuths> list = new ArrayList<>();
        list.add(sysUserAuths);
        sysUser.setSysUserAuths(list);
        return sysUser;
    }
}
