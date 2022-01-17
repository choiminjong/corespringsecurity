package io.corespringsecurity.security.init;

import io.corespringsecurity.domain.entity.*;
import io.corespringsecurity.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {

    private boolean alreadySetup = false;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private ResourcesRepository resourcesRepository;

    @Autowired
    private RoleHierarchyRepository roleHierarchyRepository;

    @Autowired
    private AccessIpRepository accessIpRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;



    private static AtomicInteger count = new AtomicInteger(0);

    @Override
    @Transactional
    public void onApplicationEvent(final ContextRefreshedEvent event) {

        if (alreadySetup) {
            return;
        }

        setupSecurityResources();

        alreadySetup = true;
    }

    private void setupSecurityResources() {

        //권한
        Role adminRole = createRoleIfNotFound("ROLE_ADMIN", "관리자");
        Role managerRole = createRoleIfNotFound("ROLE_MANAGER", "매니저");
        Role userRole = createRoleIfNotFound("ROLE_USER", "회원");

        //계정
        Set<Role> roles = new HashSet<>();
        roles.add(adminRole);
        createUserIfNotFound("admin", "1111", "admin@gmail.com", 10,  roles);

        Set<Role> roles1 = new HashSet<>();
        roles1.add(managerRole);
        createUserIfNotFound("manager", "1111", "manager@gmail.com", 20, roles1);

        Set<Role> roles2 = new HashSet<>();
        roles2.add(userRole);
        createUserIfNotFound("user", "1111", "user@gmail.com", 30, roles2);

        //url 인가
        createResourceIfNotFound("/admin/**", "", roles, "url");
        createResourceIfNotFound("/mypage", "", roles2, "url");
        createResourceIfNotFound("/config", "", roles2, "url");
        createResourceIfNotFound("/messages", "", roles1, "url");
        createResourceIfNotFound("/config", "", roles2, "url");

        //roleHierarchy
        //createRoleHierarchyIfNotFound(managerRole,adminRole);
        //createRoleHierarchyIfNotFound(userRole,managerRole);
        //setupAccessIpData();
    }

    @Transactional
    public void createRoleHierarchyIfNotFound(Role childRole, Role parentRole) {

        RoleHierarchy roleHierarchy = roleHierarchyRepository.findByChildName(parentRole.getRoleName());
        if(roleHierarchy == null){
            roleHierarchy = RoleHierarchy.builder()
                    .childName(childRole.getRoleName())
                    .build();
        }

        RoleHierarchy parentRoleHierarchy = roleHierarchyRepository.save(roleHierarchy);

        roleHierarchy = roleHierarchyRepository.findByChildName(childRole.getRoleName());
        if(roleHierarchy == null){
            roleHierarchy = RoleHierarchy.builder()
                    .childName(childRole.getRoleName())
                    .build();
        }

        RoleHierarchy childRoleHierarchy = roleHierarchyRepository.save(roleHierarchy);
        childRoleHierarchy.setParentName(parentRoleHierarchy);
        roleHierarchyRepository.save(childRoleHierarchy);
    }

    @Transactional
    public Role createRoleIfNotFound(String roleName, String roleDesc) {

        Role role = roleRepository.findByRoleName(roleName);

        if (role == null) {
            role = Role.builder()
                    .roleName(roleName)
                    .roleDesc(roleDesc)
                    .build();
        }
        return roleRepository.save(role);
    }

    @Transactional
    public Account createUserIfNotFound(String userName, String password, String email, int age, Set<Role> roleSet) {

        Account account = userRepository.findByUsername(userName);

        if (account == null) {
            account = Account.builder()
                    .username(userName)
                    .email(email)
                    .age(age)
                    .password(passwordEncoder.encode(password))
                    .userRoles(roleSet)
                    .build();
        }
        return userRepository.save(account);
    }

    @Transactional
    public Resources createResourceIfNotFound(String resourceName, String httpMethod, Set<Role> roleSet, String resourceType) {
        Resources resources = resourcesRepository.findByResourceNameAndHttpMethod(resourceName, httpMethod);

        if (resources == null) {
            resources = Resources.builder()
                    .resourceName(resourceName)
                    .roleSet(roleSet)
                    .httpMethod(httpMethod)
                    .resourceType(resourceType)
                    .orderNum(count.incrementAndGet())
                    .build();
        }
        return resourcesRepository.save(resources);
    }



    @Transactional
    public void setupAccessIpData(){
        AccessIp byIpAddress = accessIpRepository.findByIpAddress("0:0:0:0:0:0:0:1");

        if(byIpAddress == null){
            AccessIp accessIp = AccessIp.builder()
                    .ipAddress("0:0:0:0:0:0:0:1")
                    .build();
            accessIpRepository.save(accessIp);
        }

        AccessIp byIpAddress2 = accessIpRepository.findByIpAddress("127.0.0.1");

        if(byIpAddress2 == null){
            AccessIp accessIp2 = AccessIp.builder()
                    .ipAddress("127.0.0.1")
                    .build();
            accessIpRepository.save(accessIp2);
        }

    }
}