package com.canonical.charmedspark;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

public class BasicAuthenticationFilter implements Filter {

  /** Logger */
  private static final Logger LOG = LoggerFactory.getLogger(BasicAuthenticationFilter.class);

  private List<String> allowedEntities;
  private String httpHeaderName;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    this.httpHeaderName = filterConfig.getInitParameter("authorizedParameter");
    String entities = filterConfig.getInitParameter("authorizedEntities");
    String [] eList = {}; 
    if (entities != null){
      eList=entities.split(",");
    }
    
    LOG.info("Allowed users: " + Arrays.toString(eList));
    this.allowedEntities = new ArrayList<String>(Arrays.asList(eList));
  }

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
      throws IOException, ServletException {

    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;
    
    LOG.debug("doFilter");   
    HttpServletRequest httpRequest = (HttpServletRequest) request;

    String requestEntityName = request.getHeader(this.httpHeaderName);
    LOG.debug("Request Entity Name: " + requestEntityName);

    Enumeration<String> headerNames = httpRequest.getHeaderNames();
    List<String> hds = new ArrayList<>();
    if (headerNames != null) {
      while (headerNames.hasMoreElements()) {
        String header_name = headerNames.nextElement();
        hds.add(header_name);
      }
    }
    // List all the headers in the request
    LOG.debug("Input HEADERs: " + Arrays.toString(hds.toArray()));
    
    boolean authorized = false;
    // Check if user is authorized 
    if (this.allowedEntities.contains("*")){
      authorized = true;
    } else if (this.allowedEntities.contains(requestEntityName)){
      authorized = true;
    }

    if (authorized){
      response.setHeader("Authorized", "True");
      response.setHeader("AuthorizedEntity", requestEntityName);
    } else {
      LOG.info("Entity: " + requestEntityName + "is not authorized.");
      unauthorized(response);
    }

    filterChain.doFilter(servletRequest, servletResponse);
  }

  @Override
  public void destroy() {
  }

  private void unauthorized(HttpServletResponse response, String message) throws IOException {
    response.setHeader("Authorized", "False");
    response.sendError(401, message);
  }

  private void unauthorized(HttpServletResponse response) throws IOException {
    unauthorized(response, "Unauthorized");
  }

}