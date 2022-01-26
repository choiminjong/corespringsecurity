package io.corespringsecurity.security.init;

import io.corespringsecurity.service.RoleHierarchyService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;

@Component
@Slf4j
public class SecurityInitializer implements ApplicationRunner {

    @Autowired
    private RoleHierarchyService roleHierarchyService;

    @Autowired
    private RoleHierarchyImpl roleHierarchy;


    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        String allHierarchy = roleHierarchyService.findAllHierarchy();
        System.out.println("Init allHierarchy == " + allHierarchy);
        roleHierarchy.setHierarchy(allHierarchy);
    }

}