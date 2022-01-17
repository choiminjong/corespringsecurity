package io.corespringsecurity.domain.dto;

import io.corespringsecurity.domain.entity.Account;
import io.corespringsecurity.domain.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccountDto implements Serializable {

    private String id;
    private String username;
    private String email;
    private int age;
    private String password;
    private List<String> roles;

//    public Collection<? extends GrantedAuthority> getAuthorities() {
//        return roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
//    }

//    private Set<AuthorityDto> authorityDtoSet;

//    //JWT account 및 Role 권한 빌드
//    public static AccountDto from(Account account) {
//        if(account == null) return null;
//
//        return AccountDto.builder()
//                .username(account.getUsername())
//                .email(account.getEmail())
//                .authorityDtoSet(account.getUserRoles().stream()
//                        .map(authority -> AuthorityDto.builder().authorityName(authority.getRoleName()).build())
//                        .collect(Collectors.toSet()))
//                .build();
//    }

    private Set<RoleDto> roleDtoSet;

    //JWT account 및 Role 권한 빌드
    public static AccountDto from(Account account) {
        if(account == null) return null;

        return AccountDto.builder()
                .username(account.getUsername())
                .email(account.getEmail())
                .roleDtoSet(account.getUserRoles().stream()
                        .map(authority -> RoleDto.builder().roleName(authority.getRoleName()).build())
                        .collect(Collectors.toSet()))
                .build();
    }

    
}
