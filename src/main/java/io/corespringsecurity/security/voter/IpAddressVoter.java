package io.corespringsecurity.security.voter;

import io.corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

@Service
public class IpAddressVoter  implements AccessDecisionVoter<Object> {

    @Autowired
    private SecurityResourceService securityResourceService;

    public IpAddressVoter(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return (attribute.getAttribute() != null);
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    @Override
    /*
    authentication 인증정보
    object request 정보
    attributes 자원 접근 권한 정보
     */
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        //사용자의 정보를 알 수 있다. IP등등 details
        WebAuthenticationDetails details = (WebAuthenticationDetails)authentication.getDetails();
        String remoteAddress = details.getRemoteAddress();
        List<String> accessIpList = securityResourceService.getAccessIpList();

        int result = ACCESS_DENIED; // 허용되지 않음

        for(String ipAddress : accessIpList){
            if(remoteAddress.equals(ipAddress)){
                return ACCESS_ABSTAIN; // 중립
            }
        }

        //IP맞지 않는다면 바로 예외처리
        if(result == ACCESS_DENIED){
            throw new AccessDeniedException("Invalid IpAddress");
        }

        return result;
    }
}
