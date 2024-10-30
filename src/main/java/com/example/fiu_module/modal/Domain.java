package com.example.fiu_module.modal;

// import jakarta.persistence.Entity;
// import jakarta.persistence.Id;

// import jakarta.persistence.Table;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "domain")
public class Domain {

    @Id
    private String names;

    public Domain() {
    }

    public Domain(String names) {
        this.names = names;
    }

    public String getNames() {
        return names;
    }

    public void setNames(String names) {
        this.names = names;
    }
}
