package com.security.jsextractor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.HttpService;

public class SiteMapInjector {

    private final MontoyaApi api;

    public SiteMapInjector(MontoyaApi api) {
        this.api = api;
    }

    public void injectEndpoint(String host, int port, boolean isSecure, String method, String path) {
        try {
            HttpService service = HttpService.httpService(host, port, isSecure);
            HttpRequest request = HttpRequest.httpRequest(service, method.toUpperCase() + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Burp-JS-Extractor\r\n\r\n");
            HttpResponse response = HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(request, response);
            api.siteMap().add(requestResponse);
        } catch (Exception e) {
            // Log fallback
        }
    }
}
