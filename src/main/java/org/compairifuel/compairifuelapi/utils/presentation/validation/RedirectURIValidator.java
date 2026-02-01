package org.compairifuel.compairifuelapi.utils.presentation.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.apache.commons.validator.routines.UrlValidator;

import java.net.URI;

public class RedirectURIValidator implements ConstraintValidator<RedirectURI, String> {
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        UrlValidator validator = new UrlValidator(UrlValidator.ALLOW_ALL_SCHEMES | UrlValidator.NO_FRAGMENTS | UrlValidator.ALLOW_LOCAL_URLS);
        if (!validator.isValid(value)) {
            return false;
        }

        URI uri = URI.create(value);
        return uri.getUserInfo() == null;
    }
}
