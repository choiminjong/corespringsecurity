package io.corespringsecurity.service;

import io.corespringsecurity.domain.entity.AccessIp;
import io.corespringsecurity.repository.AccessIpRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SecurityResourceServiceTest {

    @Autowired
    private SecurityResourceService securityResourceService;

    @Autowired
    private AccessIpRepository accessIpRepository;
    
     @Test
    public void hello_return() throws Exception {
        String hello = "hello";
        //List<String> accessIpList = securityResourceService.getAccessIpList();
         //System.out.println("accessIpList = " + accessIpList);
         List<AccessIp> all = accessIpRepository.findAll();
         System.out.println("all = " + all);
     }
}