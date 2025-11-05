package com.ssoapp.controller;

import com.ssoapp.entity.SSOConfig;
import com.ssoapp.entity.User;
import com.ssoapp.service.SSOConfigService;
import com.ssoapp.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import java.util.Optional;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.util.*;

@Controller
@RequestMapping("/sso/saml")
@RequiredArgsConstructor
public class SAMLSSOController {

    private static final Logger logger = LoggerFactory.getLogger(SAMLSSOController.class);
    private final SSOConfigService ssoConfigService;
    private final UserService userService;

    // Your application's SP Entity ID and ACS URL - miniOrange needs these
    private static final String SP_ENTITY_ID = "http://localhost:8080/sso/saml";
    private static final String ACS_URL = "http://localhost:8080/sso/saml/acs";

    @PostMapping("/config")
    @ResponseBody
    public String configureSAML(@RequestBody Map<String, Object> configData) {
        try {
            SSOConfig config = new SSOConfig();
            config.setSsoType("SAML");

            // SAML IdP Entity ID from miniOrange
            config.setEntityId(configData.get("idpEntityId").toString());

            // SAML SSO URL from miniOrange
            config.setSsoUrl(configData.get("ssoUrl").toString());

            // X.509 Certificate from miniOrange (if provided)
            if (configData.containsKey("certificate")) {
                config.setCertificate(configData.get("certificate").toString());
            }

            // Store SP info for reference (optional)
            config.setClientId(SP_ENTITY_ID);  // Using clientId to store SP Entity ID

            config.setIsEnabled(Boolean.parseBoolean(configData.get("enabled").toString()));

            ssoConfigService.saveOrUpdateConfig(config);
            logger.info("SAML configuration saved successfully");
            return "success";
        } catch (Exception e) {
            logger.error("Error configuring SAML: ", e);
            return "error: " + e.getMessage();
        }
    }

    @GetMapping("/login")
    public String initiateSAMLLogin(HttpSession session) {
        try {
            Optional<SSOConfig> config = ssoConfigService.getConfigByType("SAML");

            if (!config.isPresent()  || !Boolean.TRUE.equals(config.get().getIsEnabled())) {
                logger.warn("SAML SSO not configured or disabled");
                return "redirect:/login?error=saml_not_configured";
            }

            // Generate SAML AuthnRequest
            String samlRequest = generateSAMLRequest(config.get());

            // Store relay state for security
            String relayState = UUID.randomUUID().toString();
            session.setAttribute("saml_relay_state", relayState);

            // Redirect to miniOrange IdP with SAML request
            String redirectUrl = config.get().getSsoUrl() +
                    "?SAMLRequest=" + samlRequest +
                    "&RelayState=" + relayState;

            logger.info("Redirecting to miniOrange SAML IdP");
            return "redirect:" + redirectUrl;
        } catch (Exception e) {
            logger.error("Error initiating SAML login: ", e);
            return "redirect:/login?error=saml_init_failed";
        }
    }

    @PostMapping("/acs**")
    public void assertionConsumerService(
            @RequestParam(required = false) String SAMLResponse,
            @RequestParam(required = false) String RelayState,
            HttpServletRequest request,
            HttpServletResponse response) throws Exception {

        logger.info("SAML ACS endpoint called - SAMLResponse: {}, RelayState: {}",
                SAMLResponse != null ? "present" : "null", RelayState);

        HttpSession session = request.getSession();

        try {
            if (SAMLResponse == null || SAMLResponse.trim().isEmpty()) {
                logger.error("No SAML response received");
                response.sendRedirect("/login?error=saml_no_response");
                return;
            }

            // Validate relay state (optional but recommended)
            String sessionRelayState = (String) session.getAttribute("saml_relay_state");
            if (sessionRelayState != null && !sessionRelayState.equals(RelayState)) {
                logger.warn("Relay state mismatch");
            }

            // Decode and parse SAML response
            Map<String, Object> samlAttributes = parseSAMLResponse(SAMLResponse);

            if (samlAttributes == null || samlAttributes.isEmpty()) {
                logger.error("Failed to parse SAML response");
                response.sendRedirect("/login?error=saml_parse_failed");
                return;
            }

            // Process user from SAML attributes
            User user = processSAMLUser(samlAttributes);

            // Create Spring Security authentication
            authenticateUser(user, request, response);

            // Redirect based on role
            String redirectUrl = getRedirectUrlByRole(user.getRole());
            logger.info("SAML login successful for user: {}, redirecting to: {}",
                    user.getUsername(), redirectUrl);
            response.sendRedirect(redirectUrl);

        } catch (Exception e) {
            logger.error("SAML ACS error: ", e);
            response.sendRedirect("/login?error=saml_validation_failed");
        } finally {
            session.removeAttribute("saml_relay_state");
        }
    }

    @GetMapping("/metadata")
    @ResponseBody
    public String getServiceProviderMetadata() {
        final String template =
                "<?xml version=\"1.0\"?>\n" +
                        "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"%s\">\n" +
                        "  <SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
                        "    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>\n" +
                        "    <AssertionConsumerService\n" +
                        "        Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
                        "        Location=\"%s\"\n" +
                        "        index=\"0\"/>\n" +
                        "  </SPSSODescriptor>\n" +
                        "</EntityDescriptor>\n";

        return String.format(template, SP_ENTITY_ID, ACS_URL);
    }


    @GetMapping("/sp-info")
    @ResponseBody
    public Map<String, String> getServiceProviderInfo() {
        // Endpoint to get SP configuration info for easy setup
        Map<String, String> spInfo = new HashMap<>();
        spInfo.put("entityId", SP_ENTITY_ID);
        spInfo.put("acsUrl", ACS_URL);
        spInfo.put("metadataUrl", "http://localhost:8080/sso/saml/metadata");
        return spInfo;
    }

    private String generateSAMLRequest(SSOConfig config) {
        try {
            // Generate a basic SAML AuthnRequest
            String samlRequest = String.format("""
                <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                    ID="_%s"
                                    Version="2.0"
                                    IssueInstant="%s"
                                    Destination="%s"
                                    AssertionConsumerServiceURL="%s"
                                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
                    <saml:Issuer>%s</saml:Issuer>
                    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                                        AllowCreate="true"/>
                </samlp:AuthnRequest>
                """,
                    UUID.randomUUID().toString(),
                    java.time.Instant.now().toString(),
                    config.getSsoUrl(),
                    ACS_URL,
                    SP_ENTITY_ID
            );

            // Encode the request
            byte[] samlBytes = samlRequest.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            String encoded = Base64.getEncoder().encodeToString(samlBytes);
            return java.net.URLEncoder.encode(encoded, java.nio.charset.StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            logger.error("Error generating SAML request: ", e);
            throw new RuntimeException("Failed to generate SAML request", e);
        }
    }

    private Map<String, Object> parseSAMLResponse(String samlResponse) {
        Map<String, Object> attributes = new HashMap<>();

        try {
            // Decode Base64 SAML response
            byte[] decodedResponse = Base64.getDecoder().decode(samlResponse);
            String xmlResponse = new String(decodedResponse, java.nio.charset.StandardCharsets.UTF_8);

            logger.debug("Decoded SAML Response: {}", xmlResponse);

            // Parse XML
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new ByteArrayInputStream(decodedResponse));

            // Extract NameID (username)
            NodeList nameIdNodes = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "NameID");
            if (nameIdNodes.getLength() > 0) {
                String nameId = nameIdNodes.item(0).getTextContent();
                attributes.put("username", nameId);
                logger.info("Extracted NameID: {}", nameId);
            }

            // Extract attributes from SAML assertion
            NodeList attributeNodes = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Attribute");
            for (int i = 0; i < attributeNodes.getLength(); i++) {
                Element attributeElement = (Element) attributeNodes.item(i);
                String attributeName = attributeElement.getAttribute("Name");

                NodeList valueNodes = attributeElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AttributeValue");
                if (valueNodes.getLength() > 0) {
                    String attributeValue = valueNodes.item(0).getTextContent();
                    attributes.put(attributeName, attributeValue);
                    logger.info("Extracted attribute: {} = {}", attributeName, attributeValue);
                }
            }

            // Map common miniOrange attributes
            mapMiniOrangeAttributes(attributes);

        } catch (Exception e) {
            logger.error("Error parsing SAML response: ", e);
            return null;
        }

        return attributes;
    }

    private void mapMiniOrangeAttributes(Map<String, Object> attributes) {
        // Map miniOrange-specific attribute names to standard names
        if (!attributes.containsKey("email") && attributes.containsKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")) {
            attributes.put("email", attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"));
        }

        if (!attributes.containsKey("username") && attributes.containsKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")) {
            attributes.put("username", attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"));
        }

        if (!attributes.containsKey("role") && attributes.containsKey("http://schemas.microsoft.com/ws/2008/06/identity/claims/role")) {
            attributes.put("role", attributes.get("http://schemas.microsoft.com/ws/2008/06/identity/claims/role"));
        }

        if (!attributes.containsKey("groups") && attributes.containsKey("http://schemas.microsoft.com/ws/2008/06/identity/claims/groups")) {
            attributes.put("groups", attributes.get("http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"));
        }
    }

    private User processSAMLUser(Map<String, Object> attributes) {
        // Extract user information from SAML attributes
        String username = extractString(attributes, "username", "NameID", "uid", "email");
        String email = extractString(attributes, "email", "mail", "emailAddress");
        String firstName = extractString(attributes, "givenName", "firstName", "first_name");
        String lastName = extractString(attributes, "sn", "surname", "lastName", "last_name");

        // Extract roles/groups from SAML
        Object rolesObj = attributes.get("role");
        if (rolesObj == null) rolesObj = attributes.get("roles");
        if (rolesObj == null) rolesObj = attributes.get("groups");
        if (rolesObj == null) rolesObj = attributes.get("memberOf");

        List<String> roles = parseRoles(rolesObj);
        String primaryRole = resolvePrimaryRole(roles);

        logger.info("Processing SAML user: username={}, email={}, role={}",
                username, email, primaryRole);

        // Create or update user in database
        Optional<User> existingUser = userService.findByUsername(username);
        User user;

        if (!existingUser.isPresent()) {
            user = new User();
            user.setUsername(username);
            user.setEmail(email != null ? email : username + "@saml.local");
            user.setRole(primaryRole);
            user.setPassword(""); // SAML users don't have local passwords
            user.setCreatedBy("SAML_SSO");
            user = userService.registerUser(user);
            logger.info("Created new SAML user: {}", username);
        } else {
            user = existingUser.get();
            // Optionally update user info from SAML provider
            if (email != null && !email.equals(user.getEmail())) {
                user.setEmail(email);
                user = userService.updateUser(user.getId(), user);
            }
            logger.info("Existing SAML user logged in: {}", username);
        }

        return user;
    }

    private void authenticateUser(User user, HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(true);

        String springRole = "ROLE_" + user.getRole().toUpperCase();
        List<SimpleGrantedAuthority> authorities = Collections.singletonList(
                new SimpleGrantedAuthority(springRole)
        );

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(user.getUsername(), null, authorities);

        SecurityContext ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(authentication);
        SecurityContextHolder.setContext(ctx);

        new HttpSessionSecurityContextRepository().saveContext(ctx, request, response);
        session.setAttribute("user", user);
    }

    private String extractString(Map<String, Object> map, String... keys) {
        for (String key : keys) {
            Object value = map.get(key);
            if (value != null) {
                String str = value.toString().trim();
                if (!str.isEmpty()) return str;
            }
        }
        return null;
    }

    private List<String> parseRoles(Object rolesObj) {
        List<String> roles = new ArrayList<>();

        if (rolesObj == null) {
            return Collections.singletonList("ENDUSER");
        }

        if (rolesObj instanceof String) {
            String roleStr = ((String) rolesObj).trim();
            if (!roleStr.isEmpty()) {
                // Handle comma-separated, semicolon-separated, or pipe-separated roles
                String[] parts = roleStr.split("[,;|]");
                for (String part : parts) {
                    String role = part.trim().toUpperCase(Locale.ROOT);
                    if (!role.isEmpty()) roles.add(role);
                }
            }
        } else if (rolesObj instanceof Collection) {
            for (Object obj : (Collection<?>) rolesObj) {
                if (obj != null) {
                    String role = obj.toString().trim().toUpperCase(Locale.ROOT);
                    if (!role.isEmpty()) roles.add(role);
                }
            }
        }

        return roles.isEmpty() ? Collections.singletonList("ENDUSER") : roles;
    }

    private String resolvePrimaryRole(List<String> roles) {
        // Priority: SUPERADMIN > ADMIN > ENDUSER
        for (String r : roles) {
            if ("SUPERADMIN".equalsIgnoreCase(r) || "ROLE_SUPERADMIN".equalsIgnoreCase(r)) {
                return "SUPERADMIN";
            }
        }
        for (String r : roles) {
            if ("ADMIN".equalsIgnoreCase(r) || "ROLE_ADMIN".equalsIgnoreCase(r)) {
                return "ADMIN";
            }
        }
        return "ENDUSER";
    }

    private String getRedirectUrlByRole(String role) {
        switch (role.toUpperCase()) {
            case "SUPERADMIN":
                return "/superadmin/dashboard";
            case "ADMIN":
                return "/admin/dashboard";
            default:
                return "/user/dashboard";
        }
    }
}