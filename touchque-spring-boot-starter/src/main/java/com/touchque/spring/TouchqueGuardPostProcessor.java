package com.touchque.spring;

import com.touchque.TouchqueClient;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.aop.framework.autoproxy.AbstractBeanFactoryAwareAdvisingPostProcessor;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.ObjectProvider;

/** Proxies beans with {@link RequireTouchque} on the class or a method (controllers), like Spring's own @Validated. */
public final class TouchqueGuardPostProcessor extends AbstractBeanFactoryAwareAdvisingPostProcessor {
    private static final long serialVersionUID = 1L;
    private final transient TouchqueGuardInterceptor interceptor;

    public TouchqueGuardPostProcessor(ObjectProvider<TouchqueClient> client, ObjectProvider<TouchqueGuardOptions> options) {
        ComposablePointcut pointcut = new ComposablePointcut(new AnnotationMatchingPointcut(RequireTouchque.class, true))
                .union(AnnotationMatchingPointcut.forMethodAnnotation(RequireTouchque.class));
        this.interceptor = new TouchqueGuardInterceptor(client, options);
        this.advisor = new DefaultPointcutAdvisor(pointcut, interceptor);
        setBeforeExistingAdvisors(true);
        setProxyTargetClass(true);
    }

    /** The guard also looks up a {@link TouchqueErrorBody} bean, the app's ObjectMapper and the properties. */
    @Override
    public void setBeanFactory(BeanFactory beanFactory) {
        super.setBeanFactory(beanFactory);
        interceptor.setBeanFactory(beanFactory);
    }
}
