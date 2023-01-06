package io.github.panxiaochao.security.jackson2.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import io.github.panxiaochao.security.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.io.IOException;

public class OAuth2ResourceOwnerPasswordDeserializer extends JsonDeserializer<OAuth2ResourceOwnerPasswordAuthenticationToken> {

    @Override
    public OAuth2ResourceOwnerPasswordAuthenticationToken deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {

        // TODO: 2022/12/21 需要自己解析
        ObjectMapper mapper = (ObjectMapper) jp.getCodec();
        JsonNode jsonNode = mapper.readTree(jp);
        String username = readJsonNode(jsonNode, "name").asText();

        OAuth2ResourceOwnerPasswordAuthenticationToken resourceOwnerPasswordAuthenticationToken =
                new OAuth2ResourceOwnerPasswordAuthenticationToken(
                        null,
                        AuthorizationGrantType.PASSWORD,
                        username,
                        null,
                        null
                );
        return resourceOwnerPasswordAuthenticationToken;

    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }
}
