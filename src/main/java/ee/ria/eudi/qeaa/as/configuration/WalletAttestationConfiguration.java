package ee.ria.eudi.qeaa.as.configuration;

import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

@Configuration
public class WalletAttestationConfiguration {

    @Bean
    public X509Certificate walletSigningCert(SslBundles sslBundles) throws KeyStoreException {
        SslBundle bundle = sslBundles.getBundle("eudi-wallet");
        return (X509Certificate) bundle.getStores().getTrustStore().getCertificate("ssl");
    }

    @Bean
    public X509Certificate walletProviderSigningCert(SslBundles sslBundles) throws KeyStoreException {
        SslBundle bundle = sslBundles.getBundle("eudi-wallet-provider");
        return (X509Certificate) bundle.getStores().getTrustStore().getCertificate("ssl");
    }
}
