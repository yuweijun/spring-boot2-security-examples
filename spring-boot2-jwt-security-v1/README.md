# README

1. run JwtSecurityV1Application
2. access http://localhost:8080/swagger-ui.html
3. POST /users/signin using username/password: admin/admin
4. click on the right top button `Authorize` and introduce it with the prefix "Bearer "

# NULL not allowed for column "ID"; SQL statement

    https://github.com/h2database/h2database/issues/3325

It is a bug of Hibernate ORM, it produces invalid SQL for H2 for unknown reason:

    https://hibernate.atlassian.net/browse/HHH-14985
    hibernate/hibernate-orm#4524

You can try to append `;MODE=LEGACY` to JDBC URL as a temporary workaround, it this mode H2 accepts incorrect attempts to insert NULL into identity column.

But you may run into some other issue like

    https://hibernate.atlassian.net/browse/HHH-15009

It that case you can try to add `;OLD_INFORMATION_SCHEMA=TRUE`, maybe it will help, maybe not.

# Syntax error in SQL statement "Create....."; expected "identifier";

USER is a reserved word in the SQL Standard and is a keyword in H2:

    https://h2database.com/html/advanced.html#keywords

You need to quote it or force quotation of all identifiers in configuration of Hibernate ORM.

You can also add `;NON_KEYWORDS=USER` to JDBC URL as a workaround.

# References

1. https://spring.io/guides/gs/securing-web/
2. https://github.com/h2database/h2database/issues/3325
3. https://hibernate.atlassian.net/browse/HHH-14985
4. https://hibernate.atlassian.net/browse/HHH-15009
5. https://h2database.com/html/advanced.html#keywords
