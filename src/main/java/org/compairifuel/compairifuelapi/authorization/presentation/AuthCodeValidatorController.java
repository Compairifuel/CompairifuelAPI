package org.compairifuel.compairifuelapi.authorization.presentation;

import jakarta.inject.Inject;
import lombok.extern.java.Log;
import org.compairifuel.compairifuelapi.authorization.service.IAuthCodeValidatorService;

@Log(topic = "AuthCodeValidatorController")
public class AuthCodeValidatorController {
    private IAuthCodeValidatorService authCodeValidatorService;

    @Inject
    public void setAuthCodeValidatorService(IAuthCodeValidatorService authCodeValidatorService) {
        this.authCodeValidatorService = authCodeValidatorService;
    }

    public boolean authenticateToken(String accessToken) {
        return authCodeValidatorService.isValid(accessToken.replace(authCodeValidatorService.getTokenType(),"").trim());
    }
}
