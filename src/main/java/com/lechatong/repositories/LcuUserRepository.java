package com.lechatong.repositories;

import com.lechatong.models.LcuUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LcuUserRepository extends JpaRepository<LcuUser, Integer> {

    public LcuUser findByUsername(String username);
}
