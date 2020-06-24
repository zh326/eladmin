package me.zhengjie.config;

import lombok.Data;
import me.zhengjie.utils.RsaUtil;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.security.PrivateKey;
import java.security.PublicKey;

@Data
@Configuration
public class RsaKey {
    private String publicKeyFile = "rsa_public.pub";
    private String privateKeyFile = "private.key";

    public PublicKey publicKey;
    public PrivateKey privateKey;

    @PostConstruct
    public void initRsaKey() throws Exception {
        String publicKeyFilePath = this.getClass().getClassLoader().getResource(publicKeyFile).getFile();
        String privateKeyFilePath = this.getClass().getClassLoader().getResource(privateKeyFile).getFile();
        publicKey = RsaUtil.getPublicKey(publicKeyFilePath);
        privateKey = RsaUtil.getPrivateKey(privateKeyFilePath);
    }
}
