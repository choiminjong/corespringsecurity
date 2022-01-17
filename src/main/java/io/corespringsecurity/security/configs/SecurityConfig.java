package io.corespringsecurity.security.configs;

import io.corespringsecurity.security.common.FormWebAuthenticationDetailsSource;
import io.corespringsecurity.security.factory.UrlResourcesMapFactoryBean;
import io.corespringsecurity.security.filter.AuthAPIProcessingFilter;
import io.corespringsecurity.security.filter.PermitAllFilter;
import io.corespringsecurity.security.handler.*;
import io.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import io.corespringsecurity.security.provider.CustomAuthenticationProvider;
import io.corespringsecurity.security.voter.IpAddressVoter;
import io.corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Autowired
    private FormWebAuthenticationDetailsSource formWebAuthenticationDetailsSource;

    @Autowired
    private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

    @Autowired
    private SecurityResourceService securityResourceService;

    //인가처리되지않도록 설정
    private String[] permitAllResources={"/","/login","/login2","/user/login/**"};


    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(ajaxAuthenticationProvider());
        auth.authenticationProvider(authenticationProvider());
    }

    @Bean
    public AuthenticationProvider ajaxAuthenticationProvider() {
        return new AjaxAuthenticationProvider(passwordEncoder());
    }


    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();//시큐리티 인증 처리하는데 사용
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()
       .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(formWebAuthenticationDetailsSource)
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
                .permitAll()
       .and()
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                .accessDeniedPage("/denied")
                .accessDeniedHandler(accessDeniedHandler())
       .and()
                .addFilterBefore(authAPIProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class)
        ;

        //ajaxConfigurer(http);
    }


//    @Override
//    protected void configure(final HttpSecurity http) throws Exception {
//        http
//                .httpBasic().disable()
//
//                .authorizeRequests(
//                        authorize -> authorize.anyRequest()
//                                .authenticated()
//                )
//
//                // REST API 기반의 처리 필터를 UsernamePasswordAuthenticationFilter의 앞에 추가합니다.
//                .addFilterBefore(authAPIProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
//                .addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class);
//
//        http.csrf().disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//    }


    //필터등록
//    @Bean
//    public AuthAPIProcessingFilter authAPIProcessingFilter() throws Exception {
//        AuthAPIProcessingFilter filter = new AuthAPIProcessingFilter();
//        filter.setAuthenticationManager(authenticationManagerBean());
//        return filter;
//    }

    @Bean
    public AuthAPIProcessingFilter authAPIProcessingFilter() throws Exception {
        AuthAPIProcessingFilter filter = new AuthAPIProcessingFilter();
        filter.setAuthenticationManager(authenticationManagerBean());
        // 해당 인증 처리 필터가 다음과 같은 인증 처리, 실패 핸들러를 사용 할 것임을 명시합니다.
        filter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
        filter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler());
        return filter;
    }


//    private void ajaxConfigurer(HttpSecurity http) throws Exception {
//        http
//                .apply(new AjaxLoginConfigurer<>())
//                .successHandlerAjax(ajaxAuthenticationSuccessHandler())
//                .failureHandlerAjax(ajaxAuthenticationFailureHandler())
//                .loginPage("/api/login")
//                .loginProcessingUrl("/api/login")
//                .setAuthenticationManager(authenticationManagerBean());
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider(passwordEncoder());
    }

    @Bean
    public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler(){
        return new AjaxAuthenticationSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler ajaxAuthenticationFailureHandler(){
        return new AjaxAuthenticationFailureHandler();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler(){
        CustomAccessDeniedHandler customAccessDeniedHandler = new CustomAccessDeniedHandler();
        customAccessDeniedHandler.setErrorPage("/denied");
        return customAccessDeniedHandler;
    }

    @Bean
    //인가(url 권한 검토)처리 필터 생성
    public PermitAllFilter customFilterSecurityInterceptor() throws Exception {
        //페이지 permitAll()
        PermitAllFilter permitAllFilter = new PermitAllFilter(permitAllResources);

        ////requestMap.put(new AntPathRequestMatcher("/admin/**"), Arrays.asList(new SecurityConfig("ROLE_USER")));
        permitAllFilter.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());

        //승인 인가처리 방식
        permitAllFilter.setAccessDecisionManager(affirmativeBased());
        permitAllFilter.setAuthenticationManager(authenticationManagerBean());
        return permitAllFilter;
    }

    /*
        여러 Voter중에 하나라도 허용되면 허용된다. (기본 전략)
     */
    private AccessDecisionManager affirmativeBased() {
        AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecistionVoters());
        return affirmativeBased;
    }

    //getAccessDecistionVoters 심의 단계
    //커스텀 roleVoter
    private List<AccessDecisionVoter<?>> getAccessDecistionVoters() {

        //List<AccessDecisionVoter<? extends Object>> accessDecisionVoters = new ArrayList<>();
        //IP 심의
        // RoleHierarchyVoter 권한 심의
        //accessDecisionVoters.add(roleVoter());
        //디폴트 new RoleVoter는 hasRole 개인으로 설정된 데이터 체크만한다. 상위 권한 여부를 체크하지않는다.
        //ex) .antMatchers("/mypage").hasRole("USER")

        IpAddressVoter ipAddressVoter = new IpAddressVoter(securityResourceService);
        //IpAddressVoter ipAddressVoter = new IpAddressVoter();
        List<AccessDecisionVoter<? extends Object>> accessDecisionVoterList = Arrays.asList(ipAddressVoter, roleVoter());
        return accessDecisionVoterList;
    }

    @Bean
    public AccessDecisionVoter<? extends Object> roleVoter() {
        RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchy());
        return  roleHierarchyVoter;
    }

    @Bean
    public RoleHierarchyImpl roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        return  roleHierarchy;
    }

    //FilterInvocationSecurityMetadataSource DB데이터를 불러와서 인가처리를 진행할 수 있도록 진행한다.
    @Bean
    public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception {
        return new UrlFilterInvocationSecurityMetadataSource(urlResourcesMapFactoryBean().getObject(),securityResourceService);

    }

    private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {
        UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
        urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);

        return urlResourcesMapFactoryBean;
    }

    //    @Bean
//    //인가(url 권한 검토)처리 필터 생성
//    public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {
//        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
//        filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
//        //승인 인가처리 방식
//        filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
//        filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
//        return filterSecurityInterceptor;
//    }



}