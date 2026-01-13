package org.compairifuel.compairifuelapi.utils.service;

public class ResponseNotOKException extends RuntimeException {
    public ResponseNotOKException(String message) {
        super(message);
    }
}
