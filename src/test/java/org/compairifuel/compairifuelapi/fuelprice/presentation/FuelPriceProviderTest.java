package org.compairifuel.compairifuelapi.fuelprice.presentation;

import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.loader.PactFolder;
import jakarta.ws.rs.core.Application;
import org.compairifuel.compairifuelapi.authorization.presentation.AuthCodeValidatorController;
import org.compairifuel.compairifuelapi.fuelprice.service.IFuelPriceService;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

@Provider("FuelPriceProvider")
@PactFolder("pacts")
@Tag("contract-test")
class FuelPriceProviderTest extends JerseyTest {
    private final IFuelPriceService fuelPriceService = mock(IFuelPriceService.class);
    private final AuthCodeValidatorController authCodeValidatorController = spy(AuthCodeValidatorController.class);

    @TestTemplate
    @ExtendWith(PactVerificationInvocationContextProvider.class)
    void pactVerificationTestTemplate(PactVerificationContext context) {
        context.verifyInteraction();
    }

    @Override
    protected Application configure() {
        return new ResourceConfig(FuelPriceController.class)
                .register(new AbstractBinder() {
                    @Override
                    protected void configure() {
                        bind(fuelPriceService).to(IFuelPriceService.class);
                        bind(authCodeValidatorController).to(AuthCodeValidatorController.class);
                    }
                });
    }

    @SuppressWarnings("JUnitMalformedDeclaration")
    @BeforeEach
    void setUp(PactVerificationContext context) throws Exception {
        this.setUp();
        context.setTarget(new HttpTestTarget("localhost", getPort(), "/prices/"));
    }
}
