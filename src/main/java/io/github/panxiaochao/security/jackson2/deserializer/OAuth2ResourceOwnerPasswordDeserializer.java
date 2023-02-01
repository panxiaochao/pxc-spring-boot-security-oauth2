package io.github.panxiaochao.security.jackson2.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import io.github.panxiaochao.security.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class OAuth2ResourceOwnerPasswordDeserializer extends JsonDeserializer<OAuth2ResourceOwnerPasswordAuthenticationToken> {

    private final TypeReference<List<GrantedAuthority>> GRANTED_AUTHORITY_LIST = new TypeReference<List<GrantedAuthority>>() {
    };

    private final TypeReference<Set<String>> GRANTED_SCOPES_SET = new TypeReference<Set<String>>() {
    };

    private final TypeReference<Map<String, Object>> GRANTED_ADDITIONALPARAMETERS_MAP = new TypeReference<Map<String, Object>>() {
    };

    @Override
    public OAuth2ResourceOwnerPasswordAuthenticationToken deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        ObjectMapper mapper = (ObjectMapper) jp.getCodec();
        JsonNode jsonNode = mapper.readTree(jp);
        String username = readJsonNode(jsonNode, "name").asText();
        boolean authenticated = readJsonNode(jsonNode, "authenticated").asBoolean();
        JsonNode principalNode = readJsonNode(jsonNode, "principal");
        Object principal = (!principalNode.isObject()) ? principalNode.asText() : mapper.readValue(principalNode.traverse(mapper), Object.class);
        List<GrantedAuthority> authorities = mapper.readValue(readJsonNode(jsonNode, "authorities").traverse(mapper), GRANTED_AUTHORITY_LIST);
        Set<String> scopes = mapper.readValue(readJsonNode(jsonNode, "scopes").traverse(mapper), GRANTED_SCOPES_SET);
        JsonNode additionalParametersNode = readJsonNode(jsonNode, "additionalParameters");
        Map<String, Object> additionalParameters =
                (!additionalParametersNode.isObject()) ? null : mapper.readValue(additionalParametersNode.traverse(mapper), GRANTED_ADDITIONALPARAMETERS_MAP);

        OAuth2ResourceOwnerPasswordAuthenticationToken resourceOwnerPasswordAuthenticationToken =
                new OAuth2ResourceOwnerPasswordAuthenticationToken(
                        authorities,
                        AuthorizationGrantType.PASSWORD,
                        principal,
                        scopes,
                        additionalParameters
                );
        resourceOwnerPasswordAuthenticationToken.setDetails(readJsonNode(jsonNode, "details"));
        return resourceOwnerPasswordAuthenticationToken;
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }
}
