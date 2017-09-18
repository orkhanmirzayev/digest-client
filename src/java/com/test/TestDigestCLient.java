/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.test;

import com.service.client.DigestService;
import com.service.client.DigestService_Service;
import java.util.ArrayList;
import java.util.List;
import javax.ejb.EJB;
import javax.jws.WebService;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.xml.ws.WebServiceRef;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.handler.HandlerResolver;
import javax.xml.ws.handler.PortInfo;

/**
 *
 * @author orkhan.mirzayev
 */
@WebService(serviceName = "TestDigestCLient")
public class TestDigestCLient {

    
    @WebServiceRef(wsdlLocation = "http://localhost:8080/DigestAuthService/DigestService?WSDL")
    DigestService_Service service;
    
    @EJB
    ClientMessageHandler messageHandler;
    
    @WebMethod(operationName = "hello")
    public String hello(@WebParam(name = "name") String txt) {
        service.setHandlerResolver(new HandlerResolver() {
            @Override
            public List<Handler> getHandlerChain(PortInfo portInfo) {
                List<Handler> list = new ArrayList<>();
                list.add(messageHandler);
                return list;
            }
        });
        DigestService dss = service.getDigestServicePort();
        
        return dss.hello(txt);
    }
}
