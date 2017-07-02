<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<sec:authentication var="principal" property="principal" />
<%@ page isELIgnored="false" %> 
<html>
<body>
<h2>Hello ${principal.username}</h2>
</body>
<security:authorize access="hasRole('ROLE_ADMIN')">
<p>
<a href="<c:url value="/admin" />" class="btn btn-default btn-flat">Admin Page</a>
</p>
</security:authorize>
<security:authorize access="hasRole('ROLE_DBA')">
<p>
<a href="<c:url value="/db" />" class="btn btn-default btn-flat">DBA Page</a>
</p>
</security:authorize>


<a href="<c:url value="/logout" />" class="btn btn-default btn-flat">Log out</a>
</html>
