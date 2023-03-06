<%@ page errorPage="ErrorPage.jsp" %>
<jsp:include page="AdminHeaderSessionLess.jsp" />

<jsp:useBean id="logout" scope="request" class="fr.paris.lutece.plugins.adminauthenticationoauth2.web.Oauth2AuthenticationJspBean" />

<% response.sendRedirect( logout.doLogout( request ));  %>

<%@ include file="AdminFooter.jsp" %>

