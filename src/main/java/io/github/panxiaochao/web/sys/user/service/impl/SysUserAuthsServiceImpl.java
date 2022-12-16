package io.github.panxiaochao.web.sys.user.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import io.github.panxiaochao.web.sys.user.entity.SysUserAuths;
import io.github.panxiaochao.web.sys.user.mapper.SysUserAuthsMapper;
import io.github.panxiaochao.web.sys.user.service.ISysUserAuthsService;
import org.springframework.stereotype.Service;

/**
 * <p>
 * 用户授权信息表 服务实现类
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
@Service
public class SysUserAuthsServiceImpl extends ServiceImpl<SysUserAuthsMapper, SysUserAuths> implements ISysUserAuthsService {

    @Override
    public SysUserAuths querySysUserByIdentity(String credentialsType, String identifier) {
        SysUserAuths sysUserAuths = this.getOne(new LambdaQueryWrapper<SysUserAuths>()
                .eq(SysUserAuths::getIdentityType, credentialsType)
                .eq(SysUserAuths::getIdentifier, identifier), false);
        if (sysUserAuths == null) {
            return null;
        }
        return sysUserAuths;
    }
}
