package io.corespringsecurity.service;

import io.corespringsecurity.domain.entity.AccessIp;
import io.corespringsecurity.domain.entity.Resources;
import io.corespringsecurity.domain.entity.Role;
import io.corespringsecurity.repository.AccessIpRepository;
import io.corespringsecurity.repository.ResourcesRepository;
import io.corespringsecurity.repository.RoleRepository;
import io.corespringsecurity.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.transaction.Transactional;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class SecurityResourceServiceTest {

    @Autowired
    private SecurityResourceService securityResourceService;
    @Autowired
    private  RoleRepository roleRepository;
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private ResourcesRepository resourcesRepository;

    @Autowired
    private AccessIpRepository accessIpRepository;

    @Test
    @Transactional
    public void hello_return(){
        List<String> accessIpList = securityResourceService.getAccessIpList();
        System.out.println("accessIpList = " + accessIpList);
     }
}