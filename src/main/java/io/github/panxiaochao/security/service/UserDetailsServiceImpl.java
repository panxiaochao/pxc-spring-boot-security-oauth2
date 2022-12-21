package io.github.panxiaochao.security.service;

import io.github.panxiaochao.web.sys.user.entity.SysUser;
import io.github.panxiaochao.web.sys.user.entity.SysUserAuths;
import io.github.panxiaochao.web.sys.user.service.ISysUserService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @author Lypxc
 */
public class UserDetailsServiceImpl implements UserDetailsService {

    @Resource
    private ISysUserService sysUserService;

    @Resource
    public PasswordEncoder passwordEncoder;

    // @Resource
    // private OauthAuthProperties oauthAuthProperties;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return loadUserByIdentityType(username, "username");
    }

    /**
     * 根据自定义模式IdentityType验证
     *
     * @param username
     * @param credentialsType
     * @return
     */
    public UserDetails loadUserByIdentityType(String username, String credentialsType) {
        SysUser sysUser = getUser(username, credentialsType);
        if (sysUser == null) {
            throw new UsernameNotFoundException("用户[" + username + "]不存在或者密码错误！");
        }
        Collection<GrantedAuthority> authList = getAuthorities(sysUser);
        String credential = sysUser.getSysUserAuths()
                .stream()
                .filter(s -> s.getIdentityType().equals(credentialsType))
                .map(SysUserAuths::getCredential).findFirst().orElse(null);
        return createUserDetails(username, credential, authList);
    }

    protected UserDetails createUserDetails(String username, String credential,
                                            Collection<? extends GrantedAuthority> authorities) {
        String password = credential;
        // 是否是明文
        // if (oauthAuthProperties.isPlainText()) {
        //     // 明文的情况下，需要加密置入
        password = passwordEncoder.encode(credential);
        // }
        return new User(username, password, true, true, true, true, authorities);
    }

    private Collection<GrantedAuthority> getAuthorities(SysUser sysUser) {
        List<GrantedAuthority> authList = new ArrayList<>();
        sysUser.getRoles().forEach(s -> authList.add(new SimpleGrantedAuthority(s.getRoleCode())));
        return authList;
    }

    private SysUser getUser(String username, String credentialsType) {
        return sysUserService.findUserByIdentityType(username, credentialsType);
    }
}
