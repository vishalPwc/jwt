package com.jwt.token.jwt.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeCreator;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.gson.JsonObject;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping(path="/jwt/v1")
public class CreateJWTToken {
    static String gcpProfileAPIUrl = "https://ecom-np-dev-gw-bjk1jveh.uc.gateway.dev/profile/v1/validate/gcp123";
	static String getMethodType = "GET";
	static String key_file_path = System.getenv().get("json-file");
	static String service_acc_email = "ecom-dev-atg-sa@ecom-np-dev-385017.iam.gserviceaccount.com";
	static String audience = "https://ecom-np-dev-apigw-2qg3ggwzvl11q.apigateway.ecom-np-dev-385017.cloud.goog";

	@ResponseBody
    @GetMapping(path = "/token",  
				 produces = MediaType.APPLICATION_JSON_VALUE)			 
	public Map getJwtToken(){
        String signedJWT = new String();
        try {
			System.out.println("jsonfile path is: "+key_file_path);
			 signedJWT = generateJwt(key_file_path,service_acc_email,audience,100000);
			//System.out.println("signedJWT : " + signedJWT);
			
		
       
      	} catch (IOException e) {
			e.printStackTrace();
		}
        return Collections.singletonMap("token", signedJWT);
    }
    
    public static String generateJwt(final String saKeyfile, final String saEmail,
		      final String audience, final int expiryLength)
		      throws FileNotFoundException, IOException {

		    Date now = new Date();
		    Date expTime = new Date(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(expiryLength));

		    // Build the JWT payload
		    JWTCreator.Builder token = JWT.create()
		        .withIssuedAt(now)
		        // Expires after 'expiryLength' seconds
		        .withExpiresAt(expTime)
		        // Must match 'issuer' in the security configuration in your
		        // swagger spec (e.g. service account email)
		        .withIssuer(saEmail)
		        // Must be either your Endpoints service name, or match the value
		        // specified as the 'x-google-audience' in the OpenAPI document
		        .withAudience(audience)
		        // Subject and email should match the service account's email
		        .withSubject(saEmail)
		        .withClaim("email", saEmail);

		    // Sign the JWT with a service account
		    FileInputStream stream = new FileInputStream(saKeyfile);
		    ServiceAccountCredentials cred = (ServiceAccountCredentials) ServiceAccountCredentials.fromStream(stream);
		    RSAPrivateKey key = (RSAPrivateKey) cred.getPrivateKey();
		    Algorithm algorithm = Algorithm.RSA256(null, key);
		    return token.sign(algorithm);
		  }

          public static String makeJwtRequest(final String signedJwt, final URL url)
		      throws IOException, ProtocolException {

		    HttpURLConnection con = (HttpURLConnection) url.openConnection();
		    con.setRequestMethod("GET");
		    con.setRequestProperty("Content-Type", "application/json");
		    con.setRequestProperty("Authorization", "Bearer " + signedJwt);

		    InputStreamReader reader = new InputStreamReader(con.getInputStream());
		    BufferedReader buffReader = new BufferedReader(reader);

		    String line;
		    StringBuilder result = new StringBuilder();
		    while ((line = buffReader.readLine()) != null) {
		      result.append(line);
		    }
		    buffReader.close();
		    return result.toString();
		  }
}
