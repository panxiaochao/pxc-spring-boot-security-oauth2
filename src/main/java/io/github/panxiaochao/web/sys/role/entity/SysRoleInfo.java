package io.github.panxiaochao.web.sys.role.entity;

import lombok.Getter;
import lombok.Setter;

/**
 * <p>
 * 角色表
 * </p>
 *
 * @author pxc creator
 * @since 2022-02-15
 */
@Getter
@Setter
public class SysRoleInfo {
    /**
     * 角色名称
     */
    private String roleName;

    /**
     * 角色code
     */
    private String roleCode;
}
