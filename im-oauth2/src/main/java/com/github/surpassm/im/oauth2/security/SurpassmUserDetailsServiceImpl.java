package com.github.surpassm.im.oauth2.security;

import com.github.surpassm.im.oauth2.entity.UserInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

/**
 * @author mc
 * @version 1.0
 * @date 2018/9/10 10:24
 * @description
 */
@Slf4j
@Component
public class SurpassmUserDetailsServiceImpl implements UserDetailsService {


	@Resource
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return buildUser(username);
	}


	private UserDetails buildUser(String username) {
		String password = bCryptPasswordEncoder.encode("123456");
		log.info("数据库密码是:"+password);
		return new UserInfo(1,username, password,
				true, true, true, true,
				AuthorityUtils.commaSeparatedStringToAuthorityList("admin,ROLE_USER"));
	}
}
