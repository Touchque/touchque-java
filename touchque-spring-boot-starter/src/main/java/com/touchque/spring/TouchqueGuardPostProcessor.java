package com.touchque.spring;

import com.touchque.TouchqueClient;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.aop.framework.autoproxy.AbstractBeanFactoryAwareAdvisingPostProcessor;
import org.springframework.beans.factory.ObjectProvider;

/** Proxies beans with {@link RequireTouchque} on the class or a method (controllers), like Spring's own @Validated. */
public final class TouchqueGuardPostProcessor extends AbstractBeanFactoryAwareAdvisingPostProcessor {
    private static final long serialVersionUID = 1L;

    public TouchqueGuardPostProcessor(ObjectProvider<TouchqueClient> client, ObjectProvider<TouchqueGuardOptions> options) {
        ComposablePointcut pointcut = new ComposablePointcut(new AnnotationMatchingPointcut(RequireTouchque.class, true))
                .union(AnnotationMatchingPointcut.forMethodAnnotation(RequireTouchque.class));
        this.advisor = new DefaultPointcutAdvisor(pointcut, new TouchqueGuardInterceptor(client, options));
        setBeforeExistingAdvisors(true);
        setProxyTargetClass(true);
    }
}
