package com.example.jwt.security.v7.security;

import com.example.jwt.security.v7.configuration.PermissionCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.access.ConfigAttribute;
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

        LOGGER.info("Looking for Pre/Post annotations for method '" + method.getName() + "' on target class '" + targetClass + "'");
        PermissionCheck permissionCheck = findAnnotation(method, targetClass, PermissionCheck.class);

        ArrayList<ConfigAttribute> attrs = new ArrayList<>(1);
        if (permissionCheck == null) {
            // There is no meta-data so return
            LOGGER.info("No expression annotations found");
            return Collections.emptyList();
        } else {
            final String type = permissionCheck.value();
            final String action = permissionCheck.action();
            String preAuthorizeAttribute = String.format("hasPermission('%s', '%s')", type, action);
            PreInvocationAttribute pre = attributeFactory.createPreInvocationAttribute(null, null, preAuthorizeAttribute);

            if (pre != null) {
                attrs.add(pre);
            }
        }
        attrs.trimToSize();
        return attrs;
    }

    private <A extends Annotation> A findAnnotation(Method method, Class<?> targetClass, Class<A> annotationClass) {
        // The method may be on an interface, but we need attributes from the target class.
        // If the target class is null, the method will be unchanged.
        Method specificMethod = ClassUtils.getMostSpecificMethod(method, targetClass);
        A annotation = AnnotationUtils.findAnnotation(specificMethod, annotationClass);

        if (annotation != null) {
            LOGGER.info("{} found on specific method: {}", annotation, specificMethod);
            return annotation;
        }

        // Check the original (e.g. interface) method
        if (specificMethod != method) {
            annotation = AnnotationUtils.findAnnotation(method, annotationClass);

            if (annotation != null) {
                LOGGER.info("{} found on: {}", annotation, method);
                return annotation;
            }
        }

        // Check the class-level (note declaringClass, not targetClass, which may not
        // actually implement the method)
        annotation = AnnotationUtils.findAnnotation(specificMethod.getDeclaringClass(), annotationClass);

        if (annotation != null) {
            LOGGER.info("{} found on: {}", annotation, specificMethod.getDeclaringClass().getName());
            return annotation;
        }

        return null;
    }
}
