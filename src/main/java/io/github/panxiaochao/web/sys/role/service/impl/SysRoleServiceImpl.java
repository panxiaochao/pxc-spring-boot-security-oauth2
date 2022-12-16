package io.github.panxiaochao.web.sys.role.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import io.github.panxiaochao.web.sys.role.entity.SysRole;
import io.github.panxiaochao.web.sys.role.mapper.SysRoleMapper;
import io.github.panxiaochao.web.sys.role.service.ISysRoleService;
import io.github.panxiaochao.web.sys.user.entity.SysUser;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * <p>
 * 角色表 服务实现类
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
@Service
public class SysRoleServiceImpl extends ServiceImpl<SysRoleMapper, SysRole> implements ISysRoleService {

    @Override
    public List<SysRole> queryRolesByUser(SysUser sysUser) {
        return this.baseMapper.queryRolesByUser(sysUser);
    }
}
