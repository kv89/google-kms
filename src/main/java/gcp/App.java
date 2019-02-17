package gcp;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.common.io.BaseEncoding;

@SpringBootApplication
@RestController
public class App {
	private static Logger log = LoggerFactory.getLogger(App.class);
	
	@Value("${google.key.name}")
	private String rsaKeyName;
	
	public static void main(String[] args) {
		SpringApplication.run(App.class, args);
	}
	
	@RequestMapping(name = "/get-rsa-public-key")
	public PublicKey getRsaPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		System.out.println("getting key : " + rsaKeyName);
		
		try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
			String keyName = rsaKeyName;
			
		    com.google.cloud.kms.v1.PublicKey pub = client.getPublicKey(keyName);

		    // Convert a PEM key to DER without taking a dependency on a third party library
		    String pemKey = pub.getPem();
		    pemKey = pemKey.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
		    pemKey = pemKey.replaceFirst("-----END PUBLIC KEY-----", "");
		    pemKey = pemKey.replaceAll("\\s", "");
		    byte[] derKey = BaseEncoding.base64().decode(pemKey);

		    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derKey);

		    if (pub.getAlgorithm().name().contains("RSA")) {
		      return KeyFactory.getInstance("RSA").generatePublic(keySpec);
		    } else if (pub.getAlgorithm().name().contains("EC")) {
		      return KeyFactory.getInstance("EC").generatePublic(keySpec);
		    } else {
		      throw new UnsupportedOperationException(String.format(
		          "key at path '%s' is of unsupported type '%s'.", keyName, pub.getAlgorithm()));
		    }
		  } catch(IOException e) {
			  log.error(e.getMessage());
			  throw e;
		  } catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		}
	}
}
