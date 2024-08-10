```java
import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.Base64;

public class DiffieHellmanExample {

    public static void main(String[] args) throws Exception {
        // Initialize two key pairs
        KeyPair keyPairA = generateKeyPair();
        KeyPair keyPairB = generateKeyPair();

        // Display public and private keys in Base64 encoding
        System.out.println("Public Key (A): " + Base64.getEncoder().encodeToString(keyPairA.getPublic().getEncoded()));
        System.out.println("Private Key (A): " + Base64.getEncoder().encodeToString(keyPairA.getPrivate().getEncoded()));

        System.out.println("Public Key (B): " + Base64.getEncoder().encodeToString(keyPairB.getPublic().getEncoded()));
        System.out.println("Private Key (B): " + Base64.getEncoder().encodeToString(keyPairB.getPrivate().getEncoded()));

        // Generate shared secret
        byte[] sharedSecretA = generateSharedSecret(keyPairA.getPrivate(), keyPairB.getPublic());
        byte[] sharedSecretB = generateSharedSecret(keyPairB.getPrivate(), keyPairA.getPublic());

        // Display the encoded shared secret
        System.out.println("Shared Secret (A): " + Base64.getEncoder().encodeToString(sharedSecretA));
        System.out.println("Shared Secret (B): " + Base64.getEncoder().encodeToString(sharedSecretB));
    }

    public static KeyPair generateKeyPair() throws Exception {
        // Generate the DH key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
        keyPairGenerator.initialize(2048);  // Key size
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        // Prepare to generate the shared secret
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }
}

```

