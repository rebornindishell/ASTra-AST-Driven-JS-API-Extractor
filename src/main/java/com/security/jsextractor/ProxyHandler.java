package com.security.jsextractor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.logging.Logging;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ProxyHandler implements ProxyResponseHandler {

    private final MontoyaApi api;
    private final Logging logging;
    private final PythonBridgeClient pythonBridge;
    private final SiteMapInjector siteMapInjector;
    private final JSExtractorTab uiTab;
    private final ExecutorService executorService;

    public ProxyHandler(MontoyaApi api, PythonBridgeClient pythonBridge, SiteMapInjector siteMapInjector, JSExtractorTab uiTab) {
        this.api = api;
        this.logging = api.logging();
        this.pythonBridge = pythonBridge;
        this.siteMapInjector = siteMapInjector;
        this.uiTab = uiTab;
        this.executorService = Executors.newFixedThreadPool(4);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        String url = interceptedResponse.request().url().toLowerCase();
        String mimeType = interceptedResponse.inferredMimeType().name().toLowerCase();

        // Scope Filter Check (Only filter if scope box is explicitly checked in UI)
        if (uiTab.isScopeFilterOnly() && !api.scope().isInScope(interceptedResponse.request().url())) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        // Broader JavaScript Asset Detection
        boolean isJS = url.endsWith(".js") || url.contains(".js?") || url.endsWith(".map") || 
                       url.contains("_buildmanifest") || url.contains("/scripts/") || 
                       url.contains("/app/") || mimeType.contains("script") || mimeType.contains("javascript");

        if (isJS) {
            String jsBody = interceptedResponse.bodyToString();
            if (jsBody != null && jsBody.trim().length() > 20) {
                executorService.submit(() -> {
                    logging.logToOutput("[+] Processing JS asset: " + interceptedResponse.request().url() + " (" + jsBody.length() + " bytes)");
                    PythonBridgeClient.ParseResponse res = pythonBridge.sendForParsing(jsBody, interceptedResponse.request().url());

                    if (res != null) {
                        if (res.endpoints != null && !res.endpoints.isEmpty()) {
                            logging.logToOutput("[+] Extracted " + res.endpoints.size() + " endpoints from " + interceptedResponse.request().url());
                            for (PythonBridgeClient.ExtractedEndpoint ep : res.endpoints) {
                                uiTab.addEndpoint(ep);
                            }
                        }
                        if (res.secrets != null && !res.secrets.isEmpty()) {
                            for (PythonBridgeClient.ExtractedSecret sec : res.secrets) {
                                uiTab.addSecret(sec);
                            }
                        }
                        if (res.flags != null && !res.flags.isEmpty()) {
                            for (PythonBridgeClient.ExtractedFlag flag : res.flags) {
                                uiTab.addFlag(flag);
                            }
                        }
                    }
                });
            }
        }

        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
}
