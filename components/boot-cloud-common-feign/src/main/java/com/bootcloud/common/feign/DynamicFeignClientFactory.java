package com.bootcloud.common.feign;

import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * 动态 Feign Client 工厂。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>用途：在“服务发现模式”和“直连模式”之间自动选择。</li>
 *   <li>原因：现有配置经常写成 http://boot-cloud-risk 这类服务名 URL，或写成 http://localhost:9540 这种直连 URL。</li>
 *   <li>目标：不改业务调用代码的前提下，兼容两种配置写法，并给出可观测日志。</li>
 * </ul>
 */
@Slf4j
public class DynamicFeignClientFactory {

    /**
     * 创建一个动态代理，实现 apiInterface，并根据 baseUrl 自动选择委托实现。
     *
     * @param apiInterface API 接口类型
     * @param baseUrlSupplier 运行期获取 baseUrl 的函数
     * @param discoveryClient 服务发现模式 client（典型是 @FeignClient(name="xxx")）
     * @param directClient 直连模式 client（典型是 @FeignClient(url="${...}")）
     * @param targetServiceId 目标服务名，用于辅助判断 baseUrl 是服务名还是直连域名
     */
    public <T> T create(
            Class<T> apiInterface,
            Supplier<String> baseUrlSupplier,
            T discoveryClient,
            T directClient,
            String targetServiceId
    ) {
        Objects.requireNonNull(apiInterface, "apiInterface");
        Objects.requireNonNull(baseUrlSupplier, "baseUrlSupplier");
        Objects.requireNonNull(discoveryClient, "discoveryClient");
        Objects.requireNonNull(directClient, "directClient");

        AtomicBoolean logged = new AtomicBoolean(false);
        InvocationHandler handler = new DynamicInvocationHandler<>(
                apiInterface,
                baseUrlSupplier,
                discoveryClient,
                directClient,
                targetServiceId,
                logged
        );
        Object proxy = Proxy.newProxyInstance(
                apiInterface.getClassLoader(),
                new Class<?>[]{apiInterface},
                handler
        );
        return apiInterface.cast(proxy);
    }

    @Slf4j
    private static final class DynamicInvocationHandler<T> implements InvocationHandler {
        private final Class<T> apiInterface;
        private final Supplier<String> baseUrlSupplier;
        private final T discoveryClient;
        private final T directClient;
        private final String targetServiceId;
        private final AtomicBoolean logged;

        private DynamicInvocationHandler(
                Class<T> apiInterface,
                Supplier<String> baseUrlSupplier,
                T discoveryClient,
                T directClient,
                String targetServiceId,
                AtomicBoolean logged
        ) {
            this.apiInterface = apiInterface;
            this.baseUrlSupplier = baseUrlSupplier;
            this.discoveryClient = discoveryClient;
            this.directClient = directClient;
            this.targetServiceId = targetServiceId;
            this.logged = logged;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (method.getDeclaringClass() == Object.class) {
                return method.invoke(this, args);
            }

            String baseUrl = null;
            try {
                baseUrl = baseUrlSupplier.get();
            } catch (Exception e) {
                log.warn("动态 Feign 选择器读取 baseUrl 失败，将回退到服务发现模式：api={}, method={}, msg={}",
                        apiInterface.getSimpleName(), method.getName(), e.getMessage());
            }

            ServiceUrlMode mode = ServiceUrlModeResolver.resolve(baseUrl, targetServiceId);
            if (logged != null && logged.compareAndSet(false, true)) {
                log.info("动态 Feign 选择器生效：api={}, targetServiceId={}, baseUrl={}, mode={}",
                        apiInterface.getSimpleName(), targetServiceId, baseUrl, mode);
            }

            T delegate = (mode == ServiceUrlMode.DIRECT) ? directClient : discoveryClient;
            try {
                return method.invoke(delegate, args);
            } catch (InvocationTargetException e) {
                Throwable target = e.getTargetException();
                if (target != null) {
                    throw target;
                }
                throw e;
            }
        }
    }
}

