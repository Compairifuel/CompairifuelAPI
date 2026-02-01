package org.compairifuel.compairifuelapi.utils.presentation.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Target({ ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = {RedirectURIValidator.class})
public @interface RedirectURI {
    String message() default "Redirect URI must be a valid uri";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
