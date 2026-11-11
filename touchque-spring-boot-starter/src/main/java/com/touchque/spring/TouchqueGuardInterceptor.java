package com.touchque.spring;

import com.touchque.LoginDetail;
import com.touchque.TouchqueClient;
import com.touchque.flow.Approval;
import com.touchque.flow.Guard;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/** Runs the Touchque guard around methods marked {@link RequireTouchque}. */
final class TouchqueGuardInterceptor implements MethodInterceptor {
    private final ObjectProvider<TouchqueClient> client;
    private final ObjectProvider<TouchqueGuardOptions> optionBeans;
    private volatile Map<String, TouchqueGuardOptions> options;

    TouchqueGuardInterceptor(ObjectProvider<TouchqueClient> client, ObjectProvider<TouchqueGuardOptions> optionBeans) {
        this.client = client;
        this.optionBeans = optionBeans;
    }

    private Map<String, TouchqueGuardOptions> options() {
        Map<String, TouchqueGuardOptions> o = options;
        if (o == null) {
            o = new HashMap<>();
            for (TouchqueGuardOptions bean : optionBeans) o.put(bean.action(), bean);
            options = o;
        }
        return o;
    }

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        Class<?> targetClass = invocation.getThis() != null ? AopUtils.getTargetClass(invocation.getThis()) : invocation.getMethod().getDeclaringClass();
        Method method = AopUtils.getMostSpecificMethod(invocation.getMethod(), targetClass);
        RequireTouchque ann = AnnotatedElementUtils.findMergedAnnotation(method, RequireTouchque.class);
        if (ann == null) ann = AnnotatedElementUtils.findMergedAnnotation(targetClass, RequireTouchque.class);
        if (ann == null) return invocation.proceed();
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (!(attrs instanceof ServletRequestAttributes servlet)) {
            throw new IllegalStateException("@RequireTouchque protects HTTP requests: " + method + " was called outside one");
        }
        HttpServletRequest request = servlet.getRequest();
        String action = ann.value();
        TouchqueGuardOptions o = options().getOrDefault(action, TouchqueGuardOptions.forAction(action));
        TouchqueGuardContext context = new TouchqueGuardContext(request, invocation.getArguments());
        String offline = request.getHeader(Guard.OFFLINE_HEADER);
        List<LoginDetail> details = o.details() != null ? o.details().apply(context) : null;
        Guard.Input input = new Guard.Input(o.user() != null ? o.user().apply(context) : TouchqueSpring.user(request), action)
                .headers(request::getHeader)
                .offline("1".equals(offline) || "true".equals(offline))
                .browserProof(o.silentSignIn() == null ? null : request.getHeader(Guard.BROWSER_HEADER))
                .details(details)
                .referenceId(o.referenceId() != null ? o.referenceId().apply(context) : null)
                .ip(TouchqueSpring.clientIp(request))
                .userAgent(request.getHeader("User-Agent"))
                .enroll(o.enroll())
                .silentSignIn(o.silentSignIn())
                .context(o.context() != null ? o.context().apply(context) : null);
        Guard.Result result = Guard.run(client.getObject(), input);
        if (result.approved() == null) throw new TouchqueStepException(result);
        request.setAttribute(TouchqueSpring.APPROVAL_ATTRIBUTE, result.approved());
        Object[] args = invocation.getArguments();
        Class<?>[] types = invocation.getMethod().getParameterTypes();
        for (int i = 0; i < types.length && i < args.length; i++) {
            if (Approval.class.equals(types[i])) args[i] = result.approved();
        }
        return invocation.proceed();
    }
}
