# including LoginAttemptsLogger for audit log

# including @IsAdmin annotation

@ including @PermissionCheck annotation

# How to interpret hasPermission in spring security

    /**
     * {@link MyDefaultMethodSecurityExpressionHandler#createSecurityExpressionRoot(Authentication, MethodInvocation)}
     * this method can inject {@link MethodInvocation} and get method info before call super.hasPermission(...)
     */
    @Override
    public boolean hasPermission(Object target, Object permission) {
        LOGGER.info("hasPermission({}, {}) for MethodInvocation : {}", target, permission, methodInvocation);
        return super.hasPermission(target, permission);
    }

This answer has already got to the heart of what it seems the OP was truly asking. I will augment that answer with a slightly deeper dive into what is going on behind the scenes with the hasPermission expression.

Let's first recap on this answer. The answerer detected that the OP really meant to be using an annotation with two parameters:

    @PreAuthorize("hasPermission(#opetussuunnitelmaDto, 'LUONTI')")

The confusion arose because the OP saw a method hasPermission in the code which took three parameters, and couldn't figure out what to pass for the first parameter. The answerer confirmed that the Spring framework itself provides that first parameter, namely the Authentication object, so in the annotation we only need to pass two arguments.

Deeper Dive

To understand what's going on in a little more detail, let's analyse how hasPermission works in Spring OOTB. I won't go into every last detail, but will sketch out the main flow of what is happening. Hopefully this will shed light not only upon which overloaded method is linked to the hasPermission SpEL expression, as the OP asks, but also will reveal a bit about how the entire ACL framework interprets the hasPermission expression under the hood; this will give us a greater confidence of what the hasPermission expression means, and thus how to interpret and use it.

So let's start from the top.

A Small Note on Pre/Post Authorization

To understand the hasPermission expression we really need to understand pre/post authorization. However, since the OP doesn't ask about that, it's assumed to be known, and I won't go into much detail about method protection via the @PreAuthorize and @PostAuthorize annotations. The reader is referred here for more info on that. Suffice it to say here that we'll assume the hasPermission expression is embedded in such an annotation in order to protect a method or return object. The hasPermission expression in turn will evaluate to true or false. If it evaluates to true, the Spring framework will allow the method call to proceed in the case of pre-authorization or will allow the object to be returned in the case of post authorization. Otherwise, it will block access. That's enough about those annotations. What we really want to know is how Spring interprets the hasPermission expression itself, to arrive at a true/false value.

The Permission Evaluator Class

So, hasPermission will evaluate to true or false. But how? Well, as alluded to by the OP, Spring delegates permission evaluation to the PermissionEvaluator object which is nested inside the MethodSecurityExpressionHandler Bean. If you've set up Spring ACL, then it's likely you've registered the AclPermissionEvaluator as the permission evaluator for Spring to use. For example, if you configured Spring ACL with code you might have something like this:

    @Bean
    public MethodSecurityExpressionHandler
    defaultMethodSecurityExpressionHandler() {
        DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
        AclPermissionEvaluator permissionEvaluator = new AclPermissionEvaluator(aclService());
        expressionHandler.setPermissionEvaluator(permissionEvaluator);
        return expressionHandler;
    }

Had you not done that, the default permission evaluator in place would have been the DenyAllPermissionEvaluator, which as I'm sure you've guessed would just deny permission in all cases: a safe default for sure.

From Annotation to Method

So, with the AclPermissionEvaluator class plugged into the Spring security framework as above, all hasPermission expressions in the Spring expression language (SpEL) will be delegated to the AclPermissionEvaluator for evaluation. I have not looked into the exact details of how the SpEL expression eventually ends up resulting calling upon methods within AclPermissionEvaluator, but I don't think such knowledge is needed to interpret what the hasPermission expression means. IMO, all that's necessary to know, at this level, is which annotation results in which method call. This has already been covered by this answer. But let me recap it here. First of all, we note that the hasPermission method is overloaded in the AclPermissionEvaluator and indeed in any implementation of PermissionEvaluator. One of the methods takes 3 arguments and the other takes 4 arguments:

    //3-Arg-Method
    boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission);
    //4-Arg-Method
    boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission);

On the other hand, the hasPermission expression has two use cases also. One of them passes in 2 arguments, and the other passes in 3 arguments. These were already pointed out in this answer. But let's label them here as expressions, rather than methods, so as not to confuse the two:

    hasPermission('#targetDomainObject', 'permission')    //2-arg-expression
    hasPermission('targetId', 'targetType', 'permission') //3-arg-expression

We can now link the two:

    If the //2-arg-expression is used, then the //3-Arg-Method is called.
    If the //3-arg-expression is used, then the //4-Arg-Method is called.

Where do the methods get their extra argument? Again, this was already answered here, but to recap, the extra argument that the Spring security framework provides based on the security context is the first argument in both cases, namely the Authentication parameter by the name of authentication. I haven't looked into how the Spring framework does this exactly, but for me it was enough to just know that Spring security can get an authentication object in this context.

OK, but what about the other arguments? Let's see this next. To avoid this answer getting too large, I'll just focus on the case where the //2-arg-expression is used and the //3-Arg-Method is called.

Parameters to the hasPermission Method

As mentioned, let's just focus on this method:

    boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission);

As discussed already, the first argument, the authentication object is inferred via Spring security. I haven't looked into exactly how that happens, but I believe all we need to know for the purposes of this post is to understand that the authentication object contains:

The user i.e. the principal e.g. "Alice"

All the roles i.e. authorities that have been granted to that user e.g. "admin" or "editor"

In Spring ACL, we refer to a principal such as "Alice", or an authority such as "editor" using the common term SID. As such, the authentication object contains not just one SID, but a whole list of them. The order of this list matters, as we'll see later on.

The remaining parameters to the hasPermission method are passed via the hasPermission expression. These are both typed as Object. Again, I'll just focus on one use case for the sake of keeping this post a bit shorter. Indeed, let's focus on a slightly modified version of the original use case that the OP mentions:

    @PreAuthorize("hasPermission(#opetussuunnitelmaDto, 'READ')")
    OpetussuunnitelmaDto addOpetussuunnitelma(OpetussuunnitelmaDto opetussuunnitelmaDto);

The usage of the # symbol in the sub-expression #opetussuunnitelmaDto is a way of specifying in SpEL that the opetussuunnitelmaDto parameter of the method addOpetussuunnitelma is passed in as the targetDomainObject of the hasPermission method.
The 'READ' parameter is simpler: it's simply passed as a String straight to the permission parameter of the hasPermission method.

Extracting Useful Info from the Parameters

So, we now know how all the parameters are supplied to this method:

    boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission);

But parameters of type Object are never much use. Spring ACL needs to convert those parameters into information is can use to access the relevant ACL info from the database and do its permission checking. It does so by delegating to the checkPermission method, which extracts info as follows:

An ordered list of SIDs is obtained from the authentication object. For example, suppose the user "Alice" is logged in and she has the "admin" and "editor" permissions. Then this list will contain SIDs for "Alice", "admin" and "editor". The variable that stores that list is List<Sid> sids. Now, the order of this list is important. Let's consider why. Suppose you are using a mixture of grant plus deny ACEs. For example, we may grant access to some object to all editors. But then we might deny it to the user Jane. If Jane, who is an editor, tries to access the object, do we deny access on the basis that she's Jane, or grant on the basis that she's an editor? For this reason, the order of the list of SIDs is important. The first one to match wins. So what controls the order in which SIDs are returned? Well, that responsibility lies with the SidRetrievalStrategy, which by default is SidRetrievalStrategyImpl. By looking at this class's getSids method, we see that the principal SID, i.e. Alice, is given the prime position in the list. Thereafter follow the granted authorities. I haven't delved into the detail of how the authorities themselves are ordered, but it looks to me like it's just insertion order, except for the case where role hierarchies are in play, in which case the order probably follows the hierarchy. It makes sense to me that Alice would be granted the first position in the list. If Alice herself has been granted/denied access to anything, then it's intuitive to think that that overrides anything she's been granted based on a role she has. For example, if we want to deny access to Alice, even though she's an editor, then that specific denial should take precedence. On the flip side, we might want to disallow all editors from accessing an object but make an exception for Alice. Again, putting Alice first in the list ensures this logic is enforced.

The permission object, which up to now is just an Object, is resolved into a list of Permission objects via the method resolvePermission. The variable that stores this is List<Permission> requiredPermission. Now, recall that we are focusing on the case where this permission is a single string, namely "READ". In this case, if Spring is left to its default behaviour, the permission resolver will use reflection to check this String against all the static constants in the class BasePermission, and will return the matching constant. The code that actually does the final conversion is the method buildFromMask in the class DefaultPermissionFactory. If no member of BasePermission is found whose name matches "READ", then the code will throw an exception. Indeed, in the case of the OP's use case, the permission given is "LUONTI", which won't match anything in BasePermission - in that case the developer would need to override BasePermission or create their own class for permissions. But we won't cover that here. We also note that in general, the expression might result in a list of permissions, but in our specific case we just get one permission for the one String that was passed into the SpEL expression.

The ACL itself, is retrieved based on the object. Actually, within the hasPermission method, the domain object gets converted to an object ID, which checkPermission then uses to query the DB for that ACL via the ACL service: Acl acl = this.aclService.readAclById(oid, sids);.

Spring now has all the information it needs to do a YES/NO check: does the currently logged in user have access to this object or not? It does so by delegating to the isGranted method on the PermissionGrantingStrategy Bean. By default, this is implemented via the DefaultPermissionGrantingStrategy.

isGranted ...We're Almost There

When we look at this method, it becomes apparent that order is indeed important for the list of ACEs within the ACL and the list of SIDs. Order is somewhat important for the list of permissions too, but less so - all it determines is which permission is interpreted as the "first" permission that denied access, if the result of the (public*) isGranted expression evaluates to false; and from what I can see this is just used for logging/debugging purposes so that an admin can try fix the most likely permission that's broken first.

For the ACEs and SIDs, order is indeed important because the first matching ACE to an SID takes precedence, and no other matches are performed for that permission. If the match results in an allow, then the entire isGranted function returns true. Else if there is no match for that permission or if there is a deny, the code moves on to the next permission and tries that. In this way, we can see that the list of permissions are checked with an OR type of logic: only one of them need to be granted for isGranted to succeed.

What about the actual logic that checks does a given ACE match a given permission and SID? Well, the SID bit is easy: just get the SID field off the ACE and compare: ace.getSid().equals(sid). If the SIDs match, an overloaded isGranted function is called, which just compares the masks:

    protected boolean isGranted(AccessControlEntry ace, Permission p) {
        return ace.getPermission().getMask() == p.getMask();
    }

IMO, this method really should have been called something like isMatching because it should return true for both allow (i.e. grant) AND deny type of permissions. It is just a matching function - the allow/deny behaviour is stored within the ace.isGranting() field. Furthermore, the function name isGranted is overloaded*, confusing matters even more.

There is also some confusion around why this doesn't use bitwise logic, but don't worry, you can easily override the method if you like, as specified in the answers to the linked question.

Conclusion

To recap, the OP originally asked:

How to interpret hasPermission in spring security?

This answer deep dives into the machinery of hasPermission to give an understanding of how to interpret it. In summary:

The hasPermission SpEL expression links to one of the overloaded hasPermission methods in the AclPermissionEvaluator in Spring ACL, with the Authentication object filled in automatically by Spring security.
Parameters to the hasPermission SpEL expression trickle down through the Spring ACL machinery.

Spring ACL checks three lists: SIDs, permissions, ACEs (the ACL itself) and for two of these lists, the order matters to determine the final YES/NO answer to the question "Does the user have access to this object?"
Only one ACE match is performed per permission, and the match is based on SID and the overloaded isGranted function, which can be overridden e.g. if the developer wants to use bitwise logic.

Footnotes

*There are two version of the isGranted function. The public one does indeed check if some permission in the list is granted to some SID. Wherease the protected one really should have been called something like isMatching as it checks for matching ACEs.

# References

1. https://www.baeldung.com/spring-boot-authentication-audit
2. https://stackoverflow.com/questions/31033200/how-to-interpret-haspermission-in-spring-security