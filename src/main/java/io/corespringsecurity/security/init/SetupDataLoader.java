package io.corespringsecurity.security.init;

import io.corespringsecurity.domain.entity.Account;
import io.corespringsecurity.domain.entity.Resources;
import io.corespringsecurity.domain.entity.Role;
import io.corespringsecurity.domain.entity.RoleHierarchy;
import io.corespringsecurity.repository.ResourcesRepository;
import io.corespringsecurity.repository.RoleHierarchyRepository;
import io.corespringsecurity.repository.RoleRepository;
import io.corespringsecurity.repository.UserRepository;
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

        //roleHierarchy 권한 삽입
        Set<RoleHierarchy> hierarchy = new HashSet<>();
        //hierarchy 해당 데이터를 어떻게 변경해야될지 모르겠습니다... add 를 추가할경우 오류가 발생합니다.
        RoleHierarchy roleHierarchy = new RoleHierarchy();
        roleHierarchy.setRoleHierarchy(hierarchy);
        roleHierarchy.setChildName("ROLE_ADMIN");
        roleHierarchyRepository.save(roleHierarchy);

        RoleHierarchy roleHierarchy2 = new RoleHierarchy();
        roleHierarchy2.setChildName("ROLE_MANAGER");
        roleHierarchyRepository.save(roleHierarchy2);


        Set<RoleHierarchy> hierarchy3 = new HashSet<>();
        RoleHierarchy roleHierarchy3 = new RoleHierarchy();
        roleHierarchy.setRoleHierarchy(hierarchy3);
        roleHierarchy3.setChildName("ROLE_USER");
        roleHierarchyRepository.save(roleHierarchy3);


        //roleHierarchy.add(new RoleHierarchy("ad",new RoleHierarchy("1","333"));
        //roleHierarchyRepository.save(new RoleHierarchy("ROLE_MANAGER",roleHierarchy));

        //RoleHierarchy roleHierarchyRole = createRoleHierarchyFound("ROLE_ADMIN",roleHierarchy);


        //계정 및 권한 생성
        Set<Role> roles = new HashSet<>();
        Role adminRole = createRoleIfNotFound("ROLE_ADMIN", "관리자");
        roles.add(adminRole);
        createUserIfNotFound("admin", "1111", "admin@gmail.com", 10,  roles);


        Set<Role> roles1 = new HashSet<>();
        Role managerRole = createRoleIfNotFound("ROLE_MANAGER", "매니저");
        roles1.add(managerRole);
        createUserIfNotFound("manager", "1111", "manager@gmail.com", 20, roles1);

        Set<Role> roles2 = new HashSet<>();
        Role childRole1 = createRoleIfNotFound("ROLE_USER", "회원");
        roles2.add(childRole1);
        createUserIfNotFound("user", "1111", "user@gmail.com", 30, roles2);

        //url 인가
        createResourceIfNotFound("/admin/**", "", roles, "url");
        createResourceIfNotFound("/mypage", "", roles2, "url");
        createResourceIfNotFound("/config", "", roles2, "url");
        createResourceIfNotFound("/messages", "", roles1, "url");
        createResourceIfNotFound("/config", "", roles2, "url");

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
}
