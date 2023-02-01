package io.github.panxiaochao.security.jackson2.mixin;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeInfo.As;
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import io.github.panxiaochao.security.jackson2.deserializer.OAuth2ResourceOwnerPasswordDeserializer;

@JsonTypeInfo(
        use = Id.CLASS,
        include = As.PROPERTY,
        property = "@class"
)
@JsonDeserialize(using = OAuth2ResourceOwnerPasswordDeserializer.class)
@JsonAutoDetect(
        fieldVisibility = Visibility.ANY,
        getterVisibility = Visibility.NONE,
        isGetterVisibility = Visibility.NONE
)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class OAuth2ResourceOwnerPasswordMixin {
    OAuth2ResourceOwnerPasswordMixin() {
    }
}
