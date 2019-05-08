package com.github.surpassm.security.config;

import com.github.surpassm.security.properties.SecurityProperties;
import com.github.surpassm.security.properties.app.Oauth2ClientProperties;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

/**
 * @author mc
 * @version 1.1v
 * OAuth 授权服务器配置
 * 实现认证服务器，spring securitySocial
 * 修改spring Authorization默认配置，生成定制token
 * AuthorizationServerConfigurerAdapter 该类针对端点、安全性、第三方配置
 */
@Configuration
@EnableAuthorizationServer
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

    @Resource
    private AuthenticationManager authenticationManager;

    @Resource
    private UserDetailsService userDetailsService;

    @Resource
    private SecurityProperties securityProperties;

    @Resource
    private TokenStore redisTokenStore;

    @Autowired(required = false)
    private JwtAccessTokenConverter jwtAccessTokenConverter;

    @Autowired(required = false)
    private TokenEnhancer jwtTokenEnhancer;


    /**
     * 端点配置
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpointsConfigurer) throws Exception {
        endpointsConfigurer
                //改变存储方式
                .tokenStore(redisTokenStore)
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService);
        if (jwtAccessTokenConverter != null && jwtTokenEnhancer !=null){
            TokenEnhancerChain chain = new TokenEnhancerChain();
            List<TokenEnhancer> enhancers = new ArrayList<TokenEnhancer>();
            enhancers.add(jwtTokenEnhancer);
            enhancers.add(jwtAccessTokenConverter);
            chain.setTokenEnhancers(enhancers);

            endpointsConfigurer
                    .tokenEnhancer(chain)
                    .accessTokenConverter(jwtAccessTokenConverter);
        }
    }

    /**
     * 客户端配置
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //令牌是存入内存中
        InMemoryClientDetailsServiceBuilder builder = clients.inMemory();
        if (ArrayUtils.isNotEmpty(securityProperties.getOAuth2().getClients())){
            for(Oauth2ClientProperties config : securityProperties.getOAuth2().getClients()){
                builder.withClient(config.getClientId())
                        //herd账号，应用名称
                        .secret(config.getClientIdSecret())
                        //过期时间，默认为7200秒
                        .accessTokenValiditySeconds(config.getAccessTokenValiditySeconds())
                        //指定当前客户端支持的授权模式 token、密码
                        .authorizedGrantTypes("refresh_token","password")
                        //请求权限
                        .scopes("all","read","write");
            }
        }
    }

	/**
	 * security 认证逻辑处理
	 */
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		//这里增加拦截器到安全认证链中，实现自定义认证，包括图片验证，短信验证，微信小程序，第三方系统，CAS单点登录
		super.configure(security);
	}
}
