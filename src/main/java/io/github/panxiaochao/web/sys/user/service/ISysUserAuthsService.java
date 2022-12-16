package io.github.panxiaochao.web.sys.user.service;

import com.baomidou.mybatisplus.extension.service.IService;
import io.github.panxiaochao.web.sys.user.entity.SysUserAuths;

/**
 * <p>
 * 用户授权信息表 服务类
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
public interface ISysUserAuthsService extends IService<SysUserAuths> {
    /**
     * 根据自定义模式IdentityType验证
     *
     * @param credentialsType
     * @param identifier
     * @return
     */
    SysUserAuths querySysUserByIdentity(String credentialsType, String identifier);
}
