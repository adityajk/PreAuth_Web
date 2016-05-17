package com.adi.config;

import com.adi.service.UserDetailsServiceImpl;
import com.adi.util.AuthoritiesConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;


@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(customAuthenticationProvider());
    }

    @Bean
    public RequestHeaderAuthenticationFilter siteMinderFilter() throws Exception{
        RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter = new RequestHeaderAuthenticationFilter();
        requestHeaderAuthenticationFilter.setPrincipalRequestHeader("SM_USER");
        requestHeaderAuthenticationFilter.setAuthenticationManager(authenticationManagerBean());
        return requestHeaderAuthenticationFilter;
    }


    @Bean
    public PreAuthenticatedAuthenticationProvider customAuthenticationProvider(){

        UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> wrapper =
                new UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken>(userDetailsService);
        PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider = new PreAuthenticatedAuthenticationProvider();
        preAuthenticatedAuthenticationProvider.setPreAuthenticatedUserDetailsService(wrapper);
        return preAuthenticatedAuthenticationProvider;

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .addFilter(siteMinderFilter())
            .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .antMatchers("/admin/**").hasAuthority(AuthoritiesConstants.ADMIN)
                .anyRequest().authenticated()
                .and()
            .logout()
                .permitAll()
                .and()
            .csrf()
                .disable()
                .headers()
                .frameOptions().disable();

    }

    /*@Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
                .withUser("user").password("password").roles("USER");
    }*/
}
