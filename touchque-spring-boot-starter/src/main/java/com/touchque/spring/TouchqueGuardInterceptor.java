package com.touchque.spring;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.touchque.LoginDetail;
import com.touchque.TouchqueClient;
import com.touchque.TouchqueConfigException;
import com.touchque.flow.Approval;
import com.touchque.flow.Guard;
import com.touchque.internal.Json;
import com.touchque.internal.SdkLog;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Runs the Touchque guard around methods marked {@link RequireTouchque}. The client bean is looked
 * up on each guarded request (the starter's is a lazy singleton, built once); while it cannot be
 * built (no API key or secret) the method answers 500 {@code misconfigured} (401 without a
 * signed-in user) and never runs.
 */
final class TouchqueGuardInterceptor implements MethodInterceptor {
    /** Why guarded methods answer 500 is logged once per process. */
    private static final AtomicBoolean NO_CLIENT_LOGGED = new AtomicBoolean();

    private final ObjectProvider<TouchqueClient> client;
    private final ObjectProvider<TouchqueGuardOptions> optionBeans;
    private volatile Map<String, TouchqueGuardOptions> options;
    private volatile BeanFactory beans;

    TouchqueGuardInterceptor(ObjectProvider<TouchqueClient> client, ObjectProvider<TouchqueGuardOptions> optionBeans) {
        this.client = client;
        this.optionBeans = optionBeans;
    }

    /** Where the {@link TouchqueErrorBody} bean, the app's ObjectMapper and the properties come from. */
    void setBeanFactory(BeanFactory beans) {
        this.beans = beans;
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
        TouchqueClient tq = client();
        Guard.Result result = tq == null ? Guard.withoutClient(input) : Guard.run(tq, input);
        if (result.approved() == null) throw new TouchqueStepException(result, response(result, o, tq));
        request.setAttribute(TouchqueSpring.APPROVAL_ATTRIBUTE, result.approved());
        Object[] args = invocation.getArguments();
        Class<?>[] types = invocation.getMethod().getParameterTypes();
        for (int i = 0; i < types.length && i < args.length; i++) {
            if (Approval.class.equals(types[i])) args[i] = result.approved();
        }
        return invocation.proceed();
    }

    /**
     * The client bean, looked up on every request like 5.0 did, so a prototype or per-tenant bean is
     * never frozen (Spring keeps a singleton and builds a failed one again). Null while it cannot be
     * built for a setup error (logged once).
     */
    private TouchqueClient client() {
        try {
            return client.getObject();
        } catch (RuntimeException e) {
            TouchqueConfigException config = configError(e);
            if (config == null) throw e;
            if (NO_CLIENT_LOGGED.compareAndSet(false, true)) {
                log(null).error(keysMissing() ? "[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured."
                        : "[Touchque] guard misconfigured: " + SdkLog.describe(config));
            }
            return null;
        }
    }

    /** The TouchqueConfigException behind a failed client bean, or null. */
    private static TouchqueConfigException configError(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof TouchqueConfigException c) return c;
        }
        return null;
    }

    /** No key or secret where the client bean reads them: touchque.api-key / api-secret, else TQ_API_KEY / TQ_API_SECRET. */
    private boolean keysMissing() {
        TouchqueProperties p = bean(TouchqueProperties.class);
        String key = p != null && p.getApiKey() != null ? p.getApiKey() : System.getenv("TQ_API_KEY");
        String secret = p != null && p.getApiSecret() != null ? p.getApiSecret() : System.getenv("TQ_API_SECRET");
        return key == null || key.isEmpty() || secret == null || secret.isEmpty();
    }

    /**
     * What to send, from {@link Guard#response}: the guard's body, or for a refusal (400 or more) the
     * errorBody's when one is set, written with the app's ObjectMapper. A 202 step never looks the
     * bean up, so two of them (none {@code @Primary}) cannot break it; refusals then keep the
     * default body.
     */
    private Guard.Response response(Guard.Result result, TouchqueGuardOptions o, TouchqueClient tq) {
        TouchqueErrorBody errorBody = result.status() < 400 ? null : o.errorBody() != null ? o.errorBody() : unique(TouchqueErrorBody.class);
        if (errorBody == null) return Guard.response(result, null);
        return Guard.response(result, errorBody, unique(ObjectMapper.class, Json.MAPPER), log(tq).logger());
    }

    /** The SDK's logger: the client's, or without one, the logger {@code touchque} when touchque.debug is on. */
    private SdkLog log(TouchqueClient tq) {
        if (tq != null) return tq.http().log();
        TouchqueProperties p = bean(TouchqueProperties.class);
        return p != null && p.isDebug() ? new SdkLog(null, true) : SdkLog.SILENT;
    }

    private <T> T bean(Class<T> type) {
        BeanFactory b = beans;
        return b == null ? null : b.getBeanProvider(type).getIfAvailable();
    }

    /** The one bean of a type (or the {@code @Primary} one), else null: two of them are not an error here. */
    private <T> T unique(Class<T> type) {
        return unique(type, null);
    }

    /** The one bean of a type (or the {@code @Primary} one), else {@code fallback}: the app's ObjectMapper, else the SDK's. */
    private <T> T unique(Class<T> type, T fallback) {
        BeanFactory b = beans;
        T bean = b == null ? null : b.getBeanProvider(type).getIfUnique();
        return bean != null ? bean : fallback;
    }
}
