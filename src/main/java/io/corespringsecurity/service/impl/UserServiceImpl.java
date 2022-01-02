package io.corespringsecurity.service.impl;

import io.corespringsecurity.domain.Account;
import io.corespringsecurity.repository.UserRepository;
import io.corespringsecurity.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service("userService")
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account) {

        userRepository.save(account);

    }
}
