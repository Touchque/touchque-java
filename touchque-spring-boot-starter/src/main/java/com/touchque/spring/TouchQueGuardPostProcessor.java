package com.touchque.spring;

import com.touchque.TouchQueClient;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.aop.framework.autoproxy.AbstractBeanFactoryAwareAdvisingPostProcessor;
import org.springframework.beans.factory.ObjectProvider;

/** Proxies beans with {@link RequireTouchQue} on the class or a method (controllers), like Spring's own @Validated. */
public final class TouchQueGuardPostProcessor extends AbstractBeanFactoryAwareAdvisingPostProcessor {
    private static final long serialVersionUID = 1L;

    public TouchQueGuardPostProcessor(ObjectProvider<TouchQueClient> client, ObjectProvider<TouchQueGuardOptions> options) {
        ComposablePointcut pointcut = new ComposablePointcut(new AnnotationMatchingPointcut(RequireTouchQue.class, true))
                .union(AnnotationMatchingPointcut.forMethodAnnotation(RequireTouchQue.class));
        this.advisor = new DefaultPointcutAdvisor(pointcut, new TouchQueGuardInterceptor(client, options));
        setBeforeExistingAdvisors(true);
        setProxyTargetClass(true);
    }
}
