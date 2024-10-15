package com.example;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;

import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Main {

    private static final String VAULT_AUTH_PATH = "v1/auth/aws/login";
    private static final String VAULT_URL = "https://seu-vault-server.com/"; // Defina a URL correta do seu Vault
    private static final String AWS_REGION = "us-east-1";  // Defina sua região da AWS
    private static final String STS_ENDPOINT = "https://sts.amazonaws.com";

    public static void main(String[] args) throws Exception {
        Main client = new Main();
        String vaultToken = client.authenticateWithVault("minha-role");
        System.out.println("Vault Token: " + vaultToken);
    }

    public String authenticateWithVault(String role) throws Exception {
        // 1. Obtenha credenciais temporárias da AWS
        AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard()
                .withRegion(AWS_REGION)
                .withCredentials(DefaultAWSCredentialsProviderChain.getInstance())
                .build();

        GetCallerIdentityRequest request = new GetCallerIdentityRequest();
        GetCallerIdentityResult response = stsClient.getCallerIdentity(request);

        // 2. Crie o payload para autenticação IAM
        String iamRequestPayload = createIamRequestPayload(role, response);

        // 3. Faça a requisição de autenticação ao Vault
        return sendAuthenticationRequestToVault(iamRequestPayload);
    }

    private String createIamRequestPayload(String role, GetCallerIdentityResult response) throws Exception {
        // 1. Gerar o timestamp e assinatura AWS SigV4 para o STS
        Map<String, String> signedHeaders = new HashMap<>();
        generateAwsSignedRequest(signedHeaders);

        // 2. Montar o payload esperado pelo Vault para autenticação IAM
        String iamRequestPayload = "{"
                + "\"role\":\"" + role + "\","
                + "\"iam_http_request_method\":\"POST\","
                + "\"iam_request_url\":\"" + STS_ENDPOINT + "\","
                + "\"iam_request_body\":\"" + Base64.getEncoder().encodeToString("Action=GetCallerIdentity&Version=2011-06-15".getBytes(StandardCharsets.UTF_8)) + "\","
                + "\"iam_request_headers\":" + new JSONObject(signedHeaders).toString() + ","
                + "}";

        return iamRequestPayload;
    }

    private String generateAwsSignedRequest(Map<String, String> signedHeaders) throws Exception {
        AWSCredentialsProvider credentialsProvider = DefaultAWSCredentialsProviderChain.getInstance();
        AWSCredentials credentials = credentialsProvider.getCredentials();

        // Configuração do signer para a requisição STS
        AWS4Signer signer = new AWS4Signer();
        signer.setServiceName("sts");
        signer.setRegionName(AWS_REGION);

        // Definir o corpo da requisição e os cabeçalhos
        Map<String, String> headers = new HashMap<>();
        headers.put("Host", "sts.amazonaws.com");
        headers.put("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");

        String body = "Action=GetCallerIdentity&Version=2011-06-15";

        // Montar a URI da requisição
        URI endpoint = new URI(STS_ENDPOINT);

        // Assinar a requisição usando o signer AWS4
        // Create a request object
        com.amazonaws.Request<?> request = new com.amazonaws.DefaultRequest<>("sts");
        request.setHttpMethod(com.amazonaws.http.HttpMethodName.POST);
        request.setEndpoint(endpoint);
        request.setContent(new java.io.ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        request.setHeaders(headers);

        // Sign the request
        signer.sign(request, credentials);

        // Extract signed headers
        signedHeaders.putAll(request.getHeaders());

        // Adicionar os cabeçalhos assinados ao mapa de signedHeaders
        signedHeaders.putAll(headers);

        return body;  // Retorna o corpo da requisição assinada
    }

    private String sendAuthenticationRequestToVault(String iamRequestPayload) throws Exception {
        String authUrl = VAULT_URL + VAULT_AUTH_PATH;
        HttpPost post = new HttpPost(authUrl);

        // Adicione o payload IAM ao corpo da requisição
        StringEntity entity = new StringEntity(iamRequestPayload);
        post.setEntity(entity);
        post.setHeader("Content-Type", "application/json");

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpResponse response = httpClient.execute(post);
            String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            return responseBody;  // Processar a resposta e extrair o token do Vault
        }
    }
}
