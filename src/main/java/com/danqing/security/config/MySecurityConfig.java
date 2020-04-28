package com.danqing.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author 丹青
 * @date 2020/4/25-17:16
 */
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);
        //定制请求的授权规则
        http.authorizeRequests().antMatchers("/").permitAll()//所有人都可以访问首页
                .antMatchers("/level1/**").hasRole("VIP1")//VIP1可以访问
                .antMatchers("/level2/**").hasRole("VIP2")//VIP2可以访问
                .antMatchers("/level3/**").hasRole("VIP3");//VIP3可以访问

        /**开启自动配置的登录功能
         * 自动配置的很多
         * 如：1、/login来到登录页面
         *      2、重定向到/login?error表示登录失败
         *      3、更多详细定制
         *      4、默认的post形式的/login代表登陆
         *      5、一旦定制了loginPage，那么loginPage的post请求就是登陆
         *      6、指定用户名和密码的属性名：usernameParameter("user")；passwordParameter("pwd")
         */
        http.formLogin().loginPage("/userlogin").usernameParameter("user").passwordParameter("pwd");//没有权限就会来到登录页面

        /**开启自动配置的注销功能
         *  1、访问/logout表示用户注销，情况session，方法需要用post
         *  2、注销成功后默认返回地址为 /login?logout
         *          定制  ： http.logout().logoutSuccessUrl("/");
         */
        http.logout().logoutSuccessUrl("/");//注销成功来到首页
        /**开启记住我功能
         *  1、rememberMeParameter("remeber")：记住我的属性名
         */
        http.rememberMe().rememberMeParameter("remeber");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth)  throws Exception {
        //super.configure(auth);
        //这样是保存在内存中，实际使用的时候要连上数据库
        auth.inMemoryAuthentication()
                    .withUser("zhangsan").password(passwordEncoder().encode("123456")).roles("VIP1","VIP2")
                .and()
                .withUser("lisi").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP3","VIP2");

    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
   /* @Bean//已过时的方法
    public static NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }*/


}
