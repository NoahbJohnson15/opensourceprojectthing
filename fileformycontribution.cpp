void FileServerRequestHandler::preprocessFile(const HTTPRequest& request,
                                              const RequestDetails &requestDetails,
                                              Poco::MemoryInputStream& message,
                                              const std::shared_ptr<StreamSocket>& socket,
                                              std::map<std::string, std::string> replaceVar)
{
    ServerURL cnxDetails(requestDetails);

    const Poco::URI::QueryParameters params = Poco::URI(request.getURI()).getQueryParameters();

    // Is this a file we read at startup - if not; it's not for serving.
    const std::string relPath = getRequestPathname(request);
    LOG_DBG("Preprocessing file: " << relPath);
    std::string preprocess = *getUncompressedFile(relPath);

    // We need to pass certain parameters from the cool html GET URI
    // to the embedded document URI. Here we extract those params
    // from the GET URI and set them in the generated html (see cool.html.m4).
    HTMLForm form(request, message);
    const std::string accessToken = form.get("access_token", "");
    const std::string accessTokenTtl = form.get("access_token_ttl", "");
    LOG_TRC("access_token=" << accessToken << ", access_token_ttl=" << accessTokenTtl);
    const std::string accessHeader = form.get("access_header", "");
    LOG_TRC("access_header=" << accessHeader);
    const std::string uiDefaults = form.get("ui_defaults", "");
    LOG_TRC("ui_defaults=" << uiDefaults);
    const std::string cssVars = form.get("css_variables", "");
    LOG_TRC("css_variables=" << cssVars);
    std::string buyProduct;
    {
        std::lock_guard<std::mutex> lock(COOLWSD::RemoteConfigMutex);
        buyProduct = COOLWSD::BuyProductUrl;
    }
    if (buyProduct.empty())
        buyProduct = form.get("buy_product", "");
    LOG_TRC("buy_product=" << buyProduct);
    const std::string postMessageOrigin = form.get("postmessage_origin", "");
    LOG_TRC("postmessage_origin" << postMessageOrigin);
    const std::string theme = form.get("theme", "");
    LOG_TRC("theme=" << theme);

    // Escape bad characters in access token.
    // This is placed directly in javascript in cool.html, we need to make sure
    // that no one can do anything nasty with their clever inputs.
    std::string escapedAccessToken, escapedAccessHeader, escapedPostmessageOrigin;
    Poco::URI::encode(accessToken, "'", escapedAccessToken);
    Poco::URI::encode(accessHeader, "'", escapedAccessHeader);
    Poco::URI::encode(postMessageOrigin, "'", escapedPostmessageOrigin);

    unsigned long tokenTtl = 0;
    if (!accessToken.empty())
    {
        if (!accessTokenTtl.empty())
        {
            try
            {
                tokenTtl = std::stoul(accessTokenTtl);
            }
            catch (const std::exception& exc)
            {
                LOG_ERR("access_token_ttl must be represented as the number of milliseconds since January 1, 1970 UTC, when the token will expire");
            }
        }
        else
        {
            LOG_INF("WOPI host did not pass optional access_token_ttl");
        }
    }

    std::string socketProxy = "false";
    if (requestDetails.isProxy())
        socketProxy = "true";
    replaceVar["SOCKET_PROXY"] = socketProxy;

    std::string responseRoot = cnxDetails.getResponseRoot();
    std::string userInterfaceMode;

    replaceVar["ACCESS_TOKEN"] = escapedAccessToken;
    replaceVar["ACCESS_TOKEN_TTL"] = std::to_string(tokenTtl);
    replaceVar["ACCESS_HEADER"] = escapedAccessHeader;
    replaceVar["HOST"] = cnxDetails.getWebSocketUrl();
    replaceVar["SERVICE_ROOT"] = responseRoot;
    replaceVar["UI_DEFAULTS"] = uiDefaultsToJSON(uiDefaults, userInterfaceMode);
    replaceVar["POSTMESSAGE_ORIGIN"] = escapedPostmessageOrigin;

    const auto& config = Application::instance().config();

    std::string protocolDebug = stringifyBoolFromConfig(config, "logging.protocol", false);
    replaceVar["PROTOCOL_DEBUG"] = protocolDebug;

    static const std::string hexifyEmbeddedUrls =
        COOLWSD::getConfigValue<bool>("hexify_embedded_urls", false) ? "true" : "false";
    replaceVar["HEXIFY_URL"] = hexifyEmbeddedUrls;


    bool useIntegrationTheme = config.getBool("user_interface.use_integration_theme", true);
    bool hasIntegrationTheme = (theme != "") && FileUtil::Stat(COOLWSD::FileServerRoot + "/browser/dist/" + theme).exists();
    const std::string themePreFix = hasIntegrationTheme && useIntegrationTheme ? theme + "/" : "";
    const std::string linkCSS("<link rel=\"stylesheet\" href=\"%s/browser/" COOLWSD_VERSION_HASH "/" + themePreFix + "%s.css\">");
    const std::string scriptJS("<script src=\"%s/browser/" COOLWSD_VERSION_HASH "/" + themePreFix + "%s.js\"></script>");

    std::string brandCSS(Poco::format(linkCSS, responseRoot, std::string(BRANDING)));
    std::string brandJS(Poco::format(scriptJS, responseRoot, std::string(BRANDING)));

#if ENABLE_SUPPORT_KEY
    const std::string keyString = config.getString("support_key", "");
    SupportKey key(keyString);
    if (!key.verify() || key.validDaysRemaining() <= 0)
    {
        brandCSS = Poco::format(linkCSS, responseRoot, std::string(BRANDING_UNSUPPORTED));
        brandJS = Poco::format(scriptJS, responseRoot, std::string(BRANDING_UNSUPPORTED));
    }
#endif

    replaceVar["BRANDING_CSS"] = brandCSS;
    replaceVar["BRANDING_JS"] = brandJS;
    replaceVar["CSS_VARIABLES"] = cssVarsToStyle(cssVars);

    // Customization related to document signing.
    std::string documentSigningDiv;
    std::string escapedDocumentSigningURL;
    const std::string documentSigningURL = config.getString("per_document.document_signing_url", "");
    if (!documentSigningURL.empty())
    {
        documentSigningDiv = "<div id=\"document-signing-bar\"></div>";
        Poco::URI::encode(documentSigningURL, "'", escapedDocumentSigningURL);
    }
    replaceVar["DOCUMENT_SIGNING_DIV"] = documentSigningDiv;
    replaceVar["DOCUMENT_SIGNING_URL"] = escapedDocumentSigningURL;

    const auto coolLogging = stringifyBoolFromConfig(config, "browser_logging", false);
    replaceVar["BROWSER_LOGGING"] = coolLogging;
    const auto groupDownloadAs = stringifyBoolFromConfig(config, "per_view.group_download_as", false);
    replaceVar["GROUP_DOWNLOAD_AS"] = groupDownloadAs;
    const unsigned int outOfFocusTimeoutSecs = config.getUInt("per_view.out_of_focus_timeout_secs", 60);
    replaceVar["OUT_OF_FOCUS_TIMEOUT_SECS"] = std::to_string(outOfFocusTimeoutSecs);
    const unsigned int idleTimeoutSecs = config.getUInt("per_view.idle_timeout_secs", 900);
    replaceVar["IDLE_TIMEOUT_SECS"] = std::to_string(idleTimeoutSecs);

    #if ENABLE_WELCOME_MESSAGE
        std::string enableWelcomeMessage = "true";
        std::string autoShowWelcome = "true";
        if (config.getBool("home_mode.enable", false))
        {
            autoShowWelcome = stringifyBoolFromConfig(config, "welcome.enable", false);
        }
    #else // configurable
        std::string enableWelcomeMessage = stringifyBoolFromConfig(config, "welcome.enable", false);
        std::string autoShowWelcome = stringifyBoolFromConfig(config, "welcome.enable", false);
    #endif

    replaceVar["ENABLE_WELCOME_MSG"] = enableWelcomeMessage;
    replaceVar["AUTO_SHOW_WELCOME"] = autoShowWelcome;

    // the config value of 'notebookbar/tabbed' or 'classic/compact' overrides the UIMode
    // from the WOPI
    std::string userInterfaceModeConfig = config.getString("user_interface.mode", "default");
    if (userInterfaceModeConfig == "compact")
        userInterfaceModeConfig = "classic";

    if (userInterfaceModeConfig == "tabbed")
        userInterfaceModeConfig = "notebookbar";

    if (userInterfaceModeConfig == "classic" || userInterfaceModeConfig == "notebookbar" || userInterfaceMode.empty())
        userInterfaceMode = userInterfaceModeConfig;

    // default to the notebookbar if the value is "default" or whatever
    // nonsensical
    if (userInterfaceMode != "classic" && userInterfaceMode != "notebookbar")
        userInterfaceMode = "notebookbar";

    replaceVar["USER_INTERFACE_MODE"] = userInterfaceMode;

    std::string uiRtlSettings;
    if (isRtlLanguage(requestDetails.getParam("lang")))
        uiRtlSettings = " dir=\"rtl\" ";
    replaceVar["UI_RTL_SETTINGS"] = uiRtlSettings;

    const std::string useIntegrationThemeString = useIntegrationTheme && hasIntegrationTheme ? "true" : "false";
    replaceVar["USE_INTEGRATION_THEME"] = useIntegrationThemeString;

    std::string enableMacrosExecution = stringifyBoolFromConfig(config, "security.enable_macros_execution", false);
    replaceVar["ENABLE_MACROS_EXECUTION"] = enableMacrosExecution;

    if (!config.getBool("feedback.show", true) && config.getBool("home_mode.enable", false))
    {
        replaceVar["AUTO_SHOW_FEEDBACK"] = "false";
    }
    else
    {
        replaceVar["AUTO_SHOW_FEEDBACK"] = "true";
    }
    replaceVar["BUYPRODUCT_URL"] = buyProduct;

    const std::string mimeType = "text/html";

    // Document signing: if endpoint URL is configured, whitelist that for
    // iframe purposes.
    std::ostringstream cspOss;
    cspOss << "Content-Security-Policy: default-src 'none'; "
        "frame-src 'self' " << WELCOME_URL << " " << FEEDBACK_URL << " " << buyProduct <<
        " blob: " << documentSigningURL << "; "
           "connect-src 'self' " << cnxDetails.getWebSocketUrl() << "; "
           "script-src 'unsafe-inline' 'self'; "
           "style-src 'self' 'unsafe-inline'; "
           "font-src 'self' data:; "
           "object-src 'self' blob:; ";

    // Frame ancestors: Allow coolwsd host, wopi host and anything configured.
    std::string configFrameAncestor = config.getString("net.frame_ancestors", "");
    std::string frameAncestors = configFrameAncestor;
    Poco::URI uriHost(cnxDetails.getWebSocketUrl());
    if (uriHost.getHost() != configFrameAncestor)
        frameAncestors += ' ' + uriHost.getHost() + ":*";

    for (const auto& param : params)
    {
        if (param.first == "WOPISrc")
        {
            std::string wopiFrameAncestor;
            Poco::URI::decode(param.second, wopiFrameAncestor);
            Poco::URI uriWopiFrameAncestor(wopiFrameAncestor);
            // Remove parameters from URL
            wopiFrameAncestor = uriWopiFrameAncestor.getHost();
            if (wopiFrameAncestor != uriHost.getHost() && wopiFrameAncestor != configFrameAncestor)
            {
                frameAncestors += ' ' + wopiFrameAncestor + ":*";
                LOG_TRC("Picking frame ancestor from WOPISrc: " << wopiFrameAncestor);
            }
            break;
        }
    }

    std::string imgSrc = "img-src 'self' data: https://www.collaboraoffice.com/";
    if (!frameAncestors.empty())
    {
        LOG_TRC("Allowed frame ancestors: " << frameAncestors);
        // X-Frame-Options supports only one ancestor, ignore that
        //(it's deprecated anyway and CSP works in all major browsers)
        // frame anchestors are also allowed for img-src in order to load the views avatars
        cspOss << imgSrc << frameAncestors << "; "
                << "frame-ancestors " << frameAncestors;
        std::string escapedFrameAncestors;
        Poco::URI::encode(frameAncestors, "'", escapedFrameAncestors);
        replaceVar["FRAME_ANCESTORS"] = escapedFrameAncestors;
    }
    else
    {
        LOG_TRC("Denied all frame ancestors");
        cspOss << imgSrc << "; ";
    }

    std::string newpreprocess;
    newpreprocess.reserve(preprocess.length() + 50);
    std::stringstream checkVar(preprocess);
    std::string medium;

     while(getline(checkVar, medium, '$'))
     {
        if(medium.substr(medium.length()-4, medium.length()) == "<!--")
            medium = medium.substr(0, medium.length()-4);
        if(medium.substr(0, 3) == "-->")
            medium = medium.substr(3, medium.length());
        if(medium == replaceVar[medium])
            newpreprocess.append(replaceVar[medium]);
        else newpreprocess.append(medium);
     }

    cspOss << "\r\n";

    std::ostringstream oss;
    oss << "HTTP/1.1 200 OK\r\n"
        "Date: " << Util::getHttpTimeNow() << "\r\n"
        "Last-Modified: " << Util::getHttpTimeNow() << "\r\n"
        "User-Agent: " << WOPI_AGENT_STRING << "\r\n"
        "Cache-Control:max-age=11059200\r\n"
        "ETag: \"" COOLWSD_VERSION_HASH "\"\r\n"
        "Content-Length: " << newpreprocess.size() << "\r\n"
        "Content-Type: " << mimeType << "\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
        "Referrer-Policy: no-referrer\r\n";

    // Append CSP to response headers too
    oss << cspOss.str();

    // Setup HTTP Public key pinning
    if ((COOLWSD::isSSLEnabled() || COOLWSD::isSSLTermination()) && config.getBool("ssl.hpkp[@enable]", false))
    {
        size_t i = 0;
        std::string pinPath = "ssl.hpkp.pins.pin[" + std::to_string(i) + ']';
        std::ostringstream hpkpOss;
        bool keysPinned = false;
        while (config.has(pinPath))
        {
            const std::string pin = config.getString(pinPath, "");
            if (!pin.empty())
            {
                hpkpOss << "pin-sha256=\"" << pin << "\"; ";
                keysPinned = true;
            }
            pinPath = "ssl.hpkp.pins.pin[" + std::to_string(++i) + ']';
        }

        if (keysPinned && config.getBool("ssl.hpkp.max_age[@enable]", false))
        {
            int maxAge = 1000; // seconds
            try
            {
                maxAge = config.getInt("ssl.hpkp.max_age", maxAge);
            }
            catch (Poco::SyntaxException& exc)
            {
                LOG_ERR("Invalid value of HPKP's max-age directive found in config file. Defaulting to "
                        << maxAge);
            }
            hpkpOss << "max-age=" << maxAge << "; ";
        }

        if (keysPinned && config.getBool("ssl.hpkp.report_uri[@enable]", false))
        {
            const std::string reportUri = config.getString("ssl.hpkp.report_uri", "");
            if (!reportUri.empty())
            {
                hpkpOss << "report-uri=" << reportUri << "; ";
            }
        }

        if (!hpkpOss.str().empty())
        {
            if (config.getBool("ssl.hpkp[@report_only]", false))
            {
                // Only send validation failure reports to reportUri while still allowing UAs to
                // connect to the server
                oss << "Public-Key-Pins-Report-Only: " << hpkpOss.str() << "\r\n";
            }
            else
            {
                oss << "Public-Key-Pins: " << hpkpOss.str() << "\r\n";
            }
        }
    }

    oss << "\r\n"
        << newpreprocess;

    socket->send(oss.str());
    LOG_TRC("Sent file: " << relPath << ": " << newpreprocess);
}
