package com.manuelr.microservices.cms.authserver.exception;

public class ConflictException extends RuntimeException {

    public ConflictException(String msg) {
        super(msg);
    }
}
