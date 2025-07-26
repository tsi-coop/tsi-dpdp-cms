package org.tsicoop.dpdpcms.framework;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.*;
import jakarta.servlet.ServletContext;
import org.json.simple.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Set;

public class JSONSchemaValidator {
    private static JSONSchemaValidator jsv = null;
    private ServletContext ctx = null;
    private JSONSchemaValidator(ServletContext ctx){
        this.ctx = ctx;
    }

    private ObjectMapper mapper = new ObjectMapper();

    protected static void createInstance(ServletContext ctx){
       jsv = new JSONSchemaValidator(ctx);
    }

    public static JSONSchemaValidator getHandle(){
        return jsv;
    }

    private JsonNode getJsonNodeFromClasspath(String name) throws IOException {
        InputStream is1 = Thread.currentThread().getContextClassLoader()
                .getResourceAsStream(name);
        return mapper.readTree(is1);
    }

    private JsonNode getJsonNodeFromStringContent(String content) throws IOException {
        return mapper.readTree(content);
    }

    private JsonNode getJsonNodeFromUrl(String url) throws IOException {
        return mapper.readTree(new URL(url));
    }

    private JsonSchema getJsonSchemaFromClasspath(String name) {
        JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V4);
        InputStream is = Thread.currentThread().getContextClassLoader()
                .getResourceAsStream(name);
        return factory.getSchema(is);
    }

    private JsonSchema getJsonSchemaFromStringContent(String schemaContent) {
        JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V4);
        return factory.getSchema(schemaContent);
    }

    private JsonSchema getJsonSchemaFromUrl(String uri) throws URISyntaxException {
        JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V4);
        return factory.getSchema(new URI(uri));
    }

    private JsonSchema getJsonSchemaFromJsonNode(JsonNode jsonNode) {
        JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V4);
        return factory.getSchema(jsonNode);
    }

    // Automatically detect version for given JsonNode
    private JsonSchema getJsonSchemaFromJsonNodeAutomaticVersion(JsonNode jsonNode) {
        JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersionDetector.detect(jsonNode));
        return factory.getSchema(jsonNode);
    }

    public Set<ValidationMessage> validateSchema(String _func, JSONObject input) throws Exception{
        Set<ValidationMessage> errors = null;
        InputStream is = new ByteArrayInputStream(input.toJSONString().getBytes());
        JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7);
        JsonSchema jsonSchema = factory.getSchema(ctx.getResourceAsStream("/WEB-INF/validator/"+_func+".jschema"));
        JsonNode jsonNode = jsv.mapper.readTree(is);
        errors = jsonSchema.validate(jsonNode);
        return errors;
    }

    public static void main(String[] args) throws Exception{
        JSONSchemaValidator jsv = new JSONSchemaValidator(null);
        JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7);
        JsonSchema jsonSchema = factory.getSchema(JSONSchemaValidator.class.getResourceAsStream("proto-get-los-workflow-schema.json"));
        JsonNode jsonNode = jsv.mapper.readTree(JSONSchemaValidator.class.getResourceAsStream(("proto-get-los-workflow.json")));
        Set<ValidationMessage> errors = jsonSchema.validate(jsonNode);
        System.out.println(errors);
    }
}
