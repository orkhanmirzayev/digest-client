/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ejb.LocalBean;
import javax.ejb.Stateless;
import javax.xml.namespace.QName;
import javax.xml.soap.Node;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import sun.misc.BASE64Encoder;

/**
 *
 * @author orkhan.mirzayev
 */
@Stateless
@LocalBean
public class ClientMessageHandler implements SOAPHandler<SOAPMessageContext> {

    @Override
    public boolean handleMessage(SOAPMessageContext context) {
        boolean outboundProperty = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
        try {

            if (outboundProperty) {
                SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
                rand.setSeed(System.currentTimeMillis());
                byte[] nonceBytes = new byte[16];
                rand.nextBytes(nonceBytes);

                //Make the created date
                DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
                df.setTimeZone(TimeZone.getTimeZone("UTC"));
                String createdDate = df.format(Calendar.getInstance().getTime());
                byte[] createdDateBytes = createdDate.getBytes("UTF-8");

                //Make the password
                byte[] passwordBytes = "123".getBytes("UTF-8");

                //SHA-1 hash the bunch of it.
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(nonceBytes);
                baos.write(createdDateBytes);
                baos.write(passwordBytes);
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                byte[] digestedPassword = md.digest(baos.toByteArray());

                //Encode the password and nonce for sending                   
                String passwordB64 = (new BASE64Encoder()).encode(digestedPassword);
                String nonceB64 = (new BASE64Encoder()).encode(nonceBytes);
                SOAPEnvelope envelope = context.getMessage().getSOAPPart().getEnvelope();
                SOAPMessage message = context.getMessage();
                SOAPFactory factory = SOAPFactory.newInstance();
                String prefix = "wsse";
                String uri = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
                SOAPElement securityElem = factory.createElement("Security", prefix, uri);

                SOAPElement timestampElem = factory.createElement("Timestamp", "wsu", uri);
                timestampElem.addAttribute(QName.valueOf("wsu:Id"), "TS-2");
                timestampElem.addAttribute(QName.valueOf("xmlns:wsu"), "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

                SOAPElement createdElem = factory.createElement("Created", "wsu", uri);
                createdElem.addTextNode(new Date().toString());
                SOAPElement expiresElem = factory.createElement("Expires", "wsu", uri);
                expiresElem.addTextNode("20000");

                timestampElem.addChildElement(createdElem);
                timestampElem.addChildElement(expiresElem);

                SOAPElement tokenElem = factory.createElement("UsernameToken", prefix, uri);
                tokenElem.addAttribute(QName.valueOf("wsu:Id"), "UsernameToken-2");
                tokenElem.addAttribute(QName.valueOf("xmlns:wsu"), "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
                SOAPElement userElem = factory.createElement("Username", prefix, uri);
                userElem.addTextNode("orkhan");

                SOAPElement pwdElem = factory.createElement("Password", prefix, uri);
                pwdElem.addTextNode(passwordB64);
                pwdElem.addAttribute(QName.valueOf("Type"), "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest");

                SOAPElement nonceElem = factory.createElement("Nonce", prefix, uri);
                nonceElem.addTextNode(nonceB64);
                nonceElem.addAttribute(QName.valueOf("EncodingType"), "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
                SOAPElement createdElem1 = factory.createElement("Created", "wsu", uri);
                createdElem.addTextNode(new Date().toString());
                tokenElem.addChildElement(userElem);
                tokenElem.addChildElement(pwdElem);
                tokenElem.addChildElement(nonceElem);
                tokenElem.addChildElement(createdElem1);
                securityElem.addChildElement(timestampElem);
                securityElem.addChildElement(tokenElem);
                SOAPHeader header = envelope.getHeader();
                if(header == null)
                    header = envelope.addHeader();
                
                header.addChildElement(securityElem);
                message.writeTo(System.out);
            }
        } catch (Exception ex) {
            Logger.getLogger(ClientMessageHandler.class.getName()).log(Level.SEVERE, null, ex);
        }

        return true;
    }

    public Set<QName> getHeaders() {
        return Collections.EMPTY_SET;
    }

    public boolean handleFault(SOAPMessageContext messageContext) {
        return true;
    }

    public void close(MessageContext context) {
    }

}
