package com.it.cas.authentication;

import org.apereo.cas.authentication.HandlerResult;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import javax.security.auth.login.FailedLoginException;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
public class Login extends AbstractUsernamePasswordAuthenticationHandler {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Login.class);
    public Login(String name, ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order)
    {
        super(name, servicesManager, principalFactory, order);
    }
    @Override
    protected HandlerResult authenticateUsernamePasswordInternal(UsernamePasswordCredential transformedCredential, String originalPassword) throws GeneralSecurityException, PreventedException {
        DriverManagerDataSource d=new DriverManagerDataSource();
        d.setDriverClassName("com.mysql.jdbc.Driver");
        d.setUrl("jdbc:mysql://127.0.0.1:3306/cas");
        d.setUsername("root");
        d.setPassword("root");
        JdbcTemplate template=new JdbcTemplate();
        template.setDataSource(d);
        String username=transformedCredential.getUsername();
        String pd=transformedCredential.getPassword();
        //查询数据库加密的的密码
        Map<String,Object> user = template.queryForMap("SELECT `password` FROM sys_user WHERE username = ?", transformedCredential.getUsername());
        if(user==null){
            throw new FailedLoginException("没有该用户");
        }
        //返回多属性（暂时不知道怎么用，没研究）
        Map<String, Object> map=new HashMap<>();
        map.put("email", "XXXXX@qq.com");
        if(transformedCredential.getPassword().equals(user.get("password").toString())){
            return createHandlerResult(transformedCredential, principalFactory.createPrincipal(username, map), null);
        }
        /*BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        if(encoder.matches(transformedCredential.getPassword(),user.get("password").toString())){
            return createHandlerResult(transformedCredential, principalFactory.createPrincipal(username, map), null);
        }*/
        throw new FailedLoginException("Sorry, login attemp failed.");
    }
}
