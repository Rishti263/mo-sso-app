package com.ssoapp.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class SamlMetadataService {

    public String generateMetadata(String entityId, String acsUrl) {
        return String.format("""
            <?xml version="1.0" encoding="UTF-8"?>
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" 
                                 entityID="%s">
                <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                                  Location="%s"
                                                  index="0"/>
                </md:SPSSODescriptor>
            </md:EntityDescriptor>
            """, entityId, acsUrl);
    }
}