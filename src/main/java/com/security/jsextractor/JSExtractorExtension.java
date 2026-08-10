package com.security.jsextractor;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class JSExtractorExtension implements BurpExtension {

    private MontoyaApi api;
    private Logging logging;
    private PythonBridgeClient pythonBridge;
    private SiteMapInjector siteMapInjector;
    private JSExtractorTab uiTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();

        logging.logToOutput("[+] JS API Extractor Montoya Extension Initializing...");

        // 1. Initialize Python REST API Client
        this.pythonBridge = new PythonBridgeClient("http://127.0.0.1:8000", logging);

        // 2. Initialize Site Map Injector
        this.siteMapInjector = new SiteMapInjector(api);

        // 3. Initialize Custom UI Tab
        this.uiTab = new JSExtractorTab(api, pythonBridge);
        api.userInterface().registerSuiteTab("JS API Extractor", uiTab.getUiComponent());

        // 4. Register Proxy Response Handler for JS Interception
        ProxyHandler proxyHandler = new ProxyHandler(api, pythonBridge, siteMapInjector, uiTab);
        api.proxy().registerResponseHandler(proxyHandler);

        logging.logToOutput("[+] JS API Extractor successfully registered with Burp Suite!");
        logging.logToOutput("[+] Python REST Bridge configured for: http://127.0.0.1:8000");
    }
}
