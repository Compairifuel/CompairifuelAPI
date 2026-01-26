package org.compairifuel.compairifuelapi.fuelprice.presentation;

import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.loader.PactFolder;
import jakarta.ws.rs.core.Application;
import org.compairifuel.compairifuelapi.authorization.presentation.AuthCodeValidatorController;
import org.compairifuel.compairifuelapi.fuelprice.service.IFuelPriceService;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;

@Provider("FuelPriceProvider")
@PactFolder("pacts")
@Tag("contract-test")
class FuelPriceProviderTest extends JerseyTest {
    @Mock
    private IFuelPriceService fuelPriceService;
    @Spy
    private AuthCodeValidatorController authCodeValidatorController;

    @InjectMocks
    private FuelPriceController sut;

    private AutoCloseable mocks;

    @TestTemplate
    @ExtendWith(PactVerificationInvocationContextProvider.class)
    void pactVerificationTestTemplate(PactVerificationContext context) {
        context.verifyInteraction();
    }

    @Override
    protected Application configure() {
        return new ResourceConfig().register(sut);
    }

    @SuppressWarnings("JUnitMalformedDeclaration")
    @BeforeEach
    void setUp(PactVerificationContext context) throws Exception {
        this.setUp();
        this.mocks = MockitoAnnotations.openMocks(this);
        context.setTarget(new HttpTestTarget("localhost", getPort(), "/prices/"));
    }

    @Override
    @AfterEach
    public void tearDown() throws Exception {
        super.tearDown();
        mocks.close();
    }
}
