package com.example.fiu_module.repository;

import  com.example.fiu_module.modal.Domain;                                                                                                           
import org.springframework.data.jpa.repository.JpaRepository;

public interface DomainRepository extends JpaRepository<Domain, String> {
}
