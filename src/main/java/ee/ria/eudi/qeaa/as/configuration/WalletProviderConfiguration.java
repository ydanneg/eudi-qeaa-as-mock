package ee.ria.eudi.qeaa.as.configuration;

import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyStore;

@Configuration
public class WalletProviderConfiguration {

    @Bean
    public KeyStore walletProviderTruststore(SslBundles sslBundles) {
        return sslBundles.getBundle("eudi-wallet-provider-ca").getStores().getTrustStore();
    }
}
