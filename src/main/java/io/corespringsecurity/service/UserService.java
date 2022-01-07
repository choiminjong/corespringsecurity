package io.corespringsecurity.service;

import io.corespringsecurity.domain.entity.Account;

public interface UserService {

    void createUser(Account account);
}
