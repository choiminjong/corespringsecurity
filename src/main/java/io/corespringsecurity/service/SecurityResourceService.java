package io.corespringsecurity.service;

import io.corespringsecurity.domain.entity.Resources;
import io.corespringsecurity.repository.ResourcesRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

@Slf4j
public class SecurityResourceService {

    private ResourcesRepository resourcesRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository) {
        this.resourcesRepository = resourcesRepository;
    }

    //권한과 자원정보를 가져온다.
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {

        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourcesList = resourcesRepository.findAllResources();

        resourcesList.forEach(re -> {
            List<ConfigAttribute> configAttributeList = new ArrayList<>();
            re.getRoleSet().forEach(role ->{
                // configAttributeList 구현체 기준으로 객체를 Role 계속 추가한다.
                configAttributeList.add(new SecurityConfig(role.getRoleName()));
                //LinkedHashMap<RequestMatcher, List<ConfigAttribute>>  해당포맷으로 추가한다.
                result.put(new AntPathRequestMatcher(re.getResourceName()),configAttributeList);
            });

        });

        return result;
    }
}