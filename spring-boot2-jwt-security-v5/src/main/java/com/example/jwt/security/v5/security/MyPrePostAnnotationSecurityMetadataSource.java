package com.example.jwt.security.v5.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PostInvocationAttribute;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.access.prepost.PreInvocationAttribute;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.security.access.prepost.PrePostInvocationAttributeFactory;
import org.springframework.util.ClassUtils;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

public class MyPrePostAnnotationSecurityMetadataSource extends PrePostAnnotationSecurityMetadataSource {

    private static final Logger LOGGER = LoggerFactory.getLogger(MyPrePostAnnotationSecurityMetadataSource.class);

    private final PrePostInvocationAttributeFactory attributeFactory;

    public MyPrePostAnnotationSecurityMetadataSource(PrePostInvocationAttributeFactory attributeFactory) {
        super(attributeFactory);
        this.attributeFactory = attributeFactory;
    }

    @Override
    public Collection<ConfigAttribute> getAttributes(Method method, Class<?> targetClass) {
        if (method.getDeclaringClass() == Object.class) {
            return Collections.emptyList();
        }

        logger.trace("Looking for Pre/Post annotations for method '" + method.getName()
            + "' on target class '" + targetClass + "'");
        PreFilter preFilter = findAnnotation(method, targetClass, PreFilter.class);
        PreAuthorize preAuthorize = findAnnotation(method, targetClass,
            PreAuthorize.class);
        PostFilter postFilter = findAnnotation(method, targetClass, PostFilter.class);
        // TODO: Can we check for void methods and throw an exception here?
        PostAuthorize postAuthorize = findAnnotation(method, targetClass,
            PostAuthorize.class);

        if (preFilter == null && preAuthorize == null && postFilter == null
            && postAuthorize == null) {
            // There is no meta-data so return
            logger.trace("No expression annotations found");
            return Collections.emptyList();
        }

        String preFilterAttribute = preFilter == null ? null : preFilter.value();
        String filterObject = preFilter == null ? null : preFilter.filterTarget();
        String preAuthorizeAttribute = preAuthorize == null ? null : preAuthorize.value();
        String postFilterAttribute = postFilter == null ? null : postFilter.value();
        String postAuthorizeAttribute = postAuthorize == null ? null : postAuthorize
            .value();

        ArrayList<ConfigAttribute> attrs = new ArrayList<>(2);

        PreInvocationAttribute pre = attributeFactory.createPreInvocationAttribute(
            preFilterAttribute, filterObject, preAuthorizeAttribute);

        if (pre != null) {
            attrs.add(pre);
        }

        PostInvocationAttribute post = attributeFactory.createPostInvocationAttribute(
            postFilterAttribute, postAuthorizeAttribute);

        if (post != null) {
            attrs.add(post);
        }

        attrs.trimToSize();

        return attrs;
    }

    private <A extends Annotation> A findAnnotation(Method method, Class<?> targetClass,
        Class<A> annotationClass) {
        // The method may be on an interface, but we need attributes from the target
        // class.
        // If the target class is null, the method will be unchanged.
        Method specificMethod = ClassUtils.getMostSpecificMethod(method, targetClass);
        A annotation = AnnotationUtils.findAnnotation(specificMethod, annotationClass);

        if (annotation != null) {
            logger.debug(annotation + " found on specific method: " + specificMethod);
            return annotation;
        }

        // Check the original (e.g. interface) method
        if (specificMethod != method) {
            annotation = AnnotationUtils.findAnnotation(method, annotationClass);

            if (annotation != null) {
                logger.debug(annotation + " found on: " + method);
                return annotation;
            }
        }

        // Check the class-level (note declaringClass, not targetClass, which may not
        // actually implement the method)
        annotation = AnnotationUtils.findAnnotation(specificMethod.getDeclaringClass(),
            annotationClass);

        if (annotation != null) {
            logger.debug(annotation + " found on: "
                + specificMethod.getDeclaringClass().getName());
            return annotation;
        }

        return null;
    }
}
