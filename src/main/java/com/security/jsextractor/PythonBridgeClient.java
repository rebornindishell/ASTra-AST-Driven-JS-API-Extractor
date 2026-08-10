package com.security.jsextractor;

import burp.api.montoya.logging.Logging;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class PythonBridgeClient {

    private final String baseUrl;
    private final Logging logging;
    private final Gson gson;

    public static class ExtractedEndpoint {
        public String method;
        public String path;
        public String source_url;
        public List<String> parameters;
        public JsonElement request_body;
        public String category;
        public boolean is_bola_candidate;
    }

    public static class ExtractedSecret {
        public String secret_type;
        public String key_name;
        public String value;
        public String source_url;
    }

    public static class ExtractedFlag {
        public String flag_type;
        public String name;
        public String snippet;
        public String source_url;
    }

    public static class ParseResponse {
        public String status = "success";
        public List<ExtractedEndpoint> endpoints = new ArrayList<>();
        public List<ExtractedSecret> secrets = new ArrayList<>();
        public List<ExtractedFlag> flags = new ArrayList<>();
    }

    public PythonBridgeClient(String baseUrl, Logging logging) {
        this.baseUrl = baseUrl;
        this.logging = logging;
        this.gson = new Gson();
    }

    public ParseResponse sendForParsing(String jsSource, String url) {
        ParseResponse response = new ParseResponse();

        try {
            URL targetUrl = new URL(baseUrl + "/parse");
            HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(15000);

            JsonObject payload = new JsonObject();
            payload.addProperty("source", jsSource);
            payload.addProperty("url", url);

            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = payload.toString().getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            int code = conn.getResponseCode();
            if (code == 200) {
                InputStreamReader reader = new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8);
                JsonObject responseJson = gson.fromJson(reader, JsonObject.class);
                
                if (responseJson != null) {
                    if (responseJson.has("endpoints") && responseJson.get("endpoints").isJsonArray()) {
                        JsonArray arr = responseJson.getAsJsonArray("endpoints");
                        for (int i = 0; i < arr.size(); i++) {
                            try {
                                ExtractedEndpoint ep = gson.fromJson(arr.get(i), ExtractedEndpoint.class);
                                if (ep != null && ep.path != null && !ep.path.trim().isEmpty()) {
                                    response.endpoints.add(ep);
                                }
                            } catch (Exception ex) {
                                logging.logToError("Error deserializing endpoint: " + ex.getMessage());
                            }
                        }
                    }

                    if (responseJson.has("secrets") && responseJson.get("secrets").isJsonArray()) {
                        JsonArray arr = responseJson.getAsJsonArray("secrets");
                        for (int i = 0; i < arr.size(); i++) {
                            try {
                                ExtractedSecret sec = gson.fromJson(arr.get(i), ExtractedSecret.class);
                                if (sec != null && sec.value != null) {
                                    response.secrets.add(sec);
                                }
                            } catch (Exception ex) {
                                logging.logToError("Error deserializing secret: " + ex.getMessage());
                            }
                        }
                    }

                    if (responseJson.has("flags") && responseJson.get("flags").isJsonArray()) {
                        JsonArray arr = responseJson.getAsJsonArray("flags");
                        for (int i = 0; i < arr.size(); i++) {
                            try {
                                ExtractedFlag flag = gson.fromJson(arr.get(i), ExtractedFlag.class);
                                if (flag != null && flag.name != null) {
                                    response.flags.add(flag);
                                }
                            } catch (Exception ex) {
                                logging.logToError("Error deserializing flag: " + ex.getMessage());
                            }
                        }
                    }
                }
            } else {
                logging.logToError("Python Bridge returned HTTP error code: " + code);
            }
        } catch (Exception e) {
            logging.logToError("Communication error with Python Bridge: " + e.getMessage());
        }

        return response;
    }
}
