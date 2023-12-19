package com.example.Ecom.Classes;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.example.Ecom.Classes.Permission.*;

@RequiredArgsConstructor
public enum Role {
    USER(
            Set.of(USER_READ)
    ),
    ADMIN(
            Set.of(ADMIN_READ,
                    ADMIN_CREATE,
                    ADMIN_DELETE,
                    ADMIN_UPDATE)
    )

    ;
    @Getter
    private final Set<Permission>permissions;

    public List<SimpleGrantedAuthority>getAuthorities(){

        var authorites = getPermissions()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toList());
        authorites.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
        return authorites;
    }
}
