package io.corespringsecurity.security.configs;

import io.corespringsecurity.security.factory.UrlResourcesMapFactoryBean;
import io.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.corespringsecurity.security.handler.CustomAuthenticationFailureHandler;
import io.corespringsecurity.security.handler.CustomAuthenticationSuccessHandler;
import io.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.corespringsecurity.security.provider.CustomAuthenticationProvider;
import io.corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Autowired
    private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

    @Autowired
    private SecurityResourceService securityResourceService;


    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();//시큐리티 인증 처리하는데 사용
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/**").permitAll()
                .anyRequest().authenticated()
       .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
                .permitAll()
        .and()
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")) //인증되지 않았을 때의 동작을
                .accessDeniedPage("/denied")
                .accessDeniedHandler(accessDeniedHandler())
        .and()
                .addFilterBefore(customFilterSecurityInterceptor(),FilterSecurityInterceptor.class)
        ;
        //http.csrf().disable();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider(passwordEncoder());
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler(){
        CustomAccessDeniedHandler customAccessDeniedHandler = new CustomAccessDeniedHandler();
        customAccessDeniedHandler.setErrorPage("/denied");
        return customAccessDeniedHandler;
    }

    @Bean
    //인가(url 권한 검토)처리 필터 생성
    public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {
        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
        filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
        //승인 인가처리 방식
        filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
        filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
        return filterSecurityInterceptor;
    }

    //여러 Voter중에 하나라도 허용되면 허용된다. (기본 전략)
    private AccessDecisionManager affirmativeBased() {
        AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecistionVoters());
        return affirmativeBased;
    }

    private List<AccessDecisionVoter<?>> getAccessDecistionVoters() {

        return Arrays.asList(new RoleVoter());
    }

    //FilterInvocationSecurityMetadataSource DB데이터를 불러와서 인가처리를 진행할 수 있도록 진행한다.
    @Bean
    public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception {
        return new UrlFilterInvocationSecurityMetadataSource();

    }

//    //FilterInvocationSecurityMetadataSource DB데이터를 불러와서 인가처리를 진행할 수 있도록 진행한다.
//    @Bean
//    public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception {
//        return new UrlFilterInvocationSecurityMetadataSource(urlResourcesMapFactoryBean().getObject());
//
//    }
//
//    //urlResourcesMapFactoryBean url 데이터를 리턴받는다.
//    private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {
//        UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
//        urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
//        return urlResourcesMapFactoryBean;
//    }
}