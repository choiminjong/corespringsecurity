package io.corespringsecurity.security.filter;

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class PermitAllFilter extends FilterSecurityInterceptor {

    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
    private boolean observeOncePerRequest = true;

    private List<RequestMatcher> permitAllRequestMatchers = new ArrayList<>();

    //인가처리가 필요없는 URL들을 확인 후 List 담는다.
    public PermitAllFilter(String...permitAllResources){
        for(String resource : permitAllResources){
            permitAllRequestMatchers.add(new AntPathRequestMatcher(resource));
        }

    }

    @Override
    //해당 메소드에서는 사용자 정보를 가져올 수 있다.
    protected InterceptorStatusToken beforeInvocation(Object object) {

        boolean permitAll = false;
        HttpServletRequest request = ((FilterInvocation) object).getRequest(); //필터 호출
        for(RequestMatcher requestMatcher : permitAllRequestMatchers){

            //request 데이터가와 매칭되면 권한검사를 하지 않는다.
            if(requestMatcher.matches(request)){
                permitAll = true;
                break;
            }
        }

        if(permitAll){
            /*
            return  null 주면 권한 검사를 하지않는다.
            예를들으서 권한검사는 메소드 "UrlFilterInvocationSecurityMetadataSource->getAttributes" 해당부분을
            null바꾸면 권한검사를 하지않는다.
             */

            return  null;
        }

        return super.beforeInvocation(object);
    }



    @Override
    public void invoke(FilterInvocation fi) throws IOException, ServletException {

        if ((fi.getRequest() != null) && (fi.getRequest().getAttribute(FILTER_APPLIED) != null)
                && super.isObserveOncePerRequest()) {
            // filter already applied to this request and user wants us to observe
            // once-per-request handling, so don't re-do security checking
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } else {
            // first time this request being called, so perform security checking
            if (fi.getRequest() != null) {
                fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
            }

            //beforeInvocation 가기전 인가처리 진행
            InterceptorStatusToken token = beforeInvocation(fi);

            try {
                fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
            } finally {
                super.finallyInvocation(token);
            }

            super.afterInvocation(token, null);
        }
    }

}
