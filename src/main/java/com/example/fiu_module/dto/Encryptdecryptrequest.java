package com.example.fiu_module.dto;

public class Encryptdecryptrequest {
    private String data;
    private String salt;

    // Getters and Setters
    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
