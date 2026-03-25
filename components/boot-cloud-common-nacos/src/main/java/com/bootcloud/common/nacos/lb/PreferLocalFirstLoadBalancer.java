package com.bootcloud.common.nacos.lb;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.DefaultResponse;
import org.springframework.cloud.client.loadbalancer.EmptyResponse;
import org.springframework.cloud.client.loadbalancer.Request;
import org.springframework.cloud.client.loadbalancer.RequestData;
import org.springframework.cloud.client.loadbalancer.RequestDataContext;
import org.springframework.cloud.client.loadbalancer.Response;
import org.springframework.cloud.loadbalancer.core.ReactorServiceInstanceLoadBalancer;
import org.springframework.cloud.loadbalancer.core.ServiceInstanceListSupplier;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 本机实例优先的 LoadBalancer。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>当本机在 Nacos 注册了服务实例（host 属于本机 IP）时优先挑选本机实例。</li>
 *   <li>当本机实例不存在时自动回退到默认的轮询策略。</li>
 * </ul>
 */
@Slf4j
public class PreferLocalFirstLoadBalancer implements ReactorServiceInstanceLoadBalancer {

    private final ObjectProvider<ServiceInstanceListSupplier> supplierProvider;
    private final String serviceId;
    private final PreferLocalLoadBalancerProperties props;
    private final AtomicInteger position;
    private final Set<String> localIpSet;

    public PreferLocalFirstLoadBalancer(
            ObjectProvider<ServiceInstanceListSupplier> supplierProvider,
            String serviceId,
            PreferLocalLoadBalancerProperties props
    ) {
        this.supplierProvider = supplierProvider;
        this.serviceId = serviceId;
        this.props = props;
        this.position = new AtomicInteger(0);
        this.localIpSet = Collections.unmodifiableSet(resolveLocalIps(props));

        if (log.isInfoEnabled()) {
            log.info("本机优先负载均衡已初始化：serviceId={}, enabled={}, detectLocalIps={}, localIps={}",
                    serviceId, props.isEnabled(), props.isDetectLocalIps(), this.localIpSet);
        }
    }

    @Override
    public Mono<Response<ServiceInstance>> choose(Request request) {
        ServiceInstanceListSupplier supplier = supplierProvider == null ? null : supplierProvider.getIfAvailable();
        if (supplier == null) {
            log.warn("LoadBalancer 未获取到实例提供者：serviceId={}", serviceId);
            return Mono.just(new EmptyResponse());
        }
        String callerIp = resolveCallerIpFromRequest(request, props);
        return supplier.get(request).next().map(instances -> chooseFromList(instances, callerIp));
    }

    private Response<ServiceInstance> chooseFromList(List<ServiceInstance> instances, String callerIp) {
        if (instances == null || instances.isEmpty()) {
            log.warn("LoadBalancer 未发现可用实例：serviceId={}", serviceId);
            return new EmptyResponse();
        }

        // 1) 按调用方 IP 优先（默认关闭，主要给入口服务使用）
        if (props.isEnabled() && props.isPreferCallerIp() && StringUtils.hasText(callerIp)) {
            List<ServiceInstance> preferred = filterByHost(instances, callerIp.trim());
            if (!preferred.isEmpty()) {
                ServiceInstance chosen = roundRobin(preferred);
                if (log.isDebugEnabled()) {
                    log.debug("LoadBalancer 按调用方 IP 选择实例：serviceId={}, callerIp={}, chosen={}:{}, preferredCount={}, total={}",
                            serviceId, callerIp, chosen.getHost(), chosen.getPort(), preferred.size(), instances.size());
                }
                return new DefaultResponse(chosen);
            }
        }

        // 2) 本机优先（核心能力）
        if (!props.isEnabled() || localIpSet.isEmpty()) {
            ServiceInstance chosen = roundRobin(instances);
            if (log.isDebugEnabled()) {
                log.debug("LoadBalancer 普通选择：serviceId={}, chosen={}:{}, total={}",
                        serviceId, chosen.getHost(), chosen.getPort(), instances.size());
            }
            return new DefaultResponse(chosen);
        }

        List<ServiceInstance> local = new ArrayList<>();
        for (ServiceInstance si : instances) {
            String host = si == null ? null : si.getHost();
            if (StringUtils.hasText(host) && localIpSet.contains(host.trim())) {
                local.add(si);
            }
        }

        if (!local.isEmpty()) {
            ServiceInstance chosen = roundRobin(local);
            if (log.isDebugEnabled()) {
                log.debug("LoadBalancer 选择本机实例：serviceId={}, chosen={}:{}, localCount={}, total={}",
                        serviceId, chosen.getHost(), chosen.getPort(), local.size(), instances.size());
            }
            return new DefaultResponse(chosen);
        }

        ServiceInstance chosen = roundRobin(instances);
        if (log.isDebugEnabled()) {
            log.debug("LoadBalancer 未找到本机实例，回退普通选择：serviceId={}, chosen={}:{}, total={}",
                    serviceId, chosen.getHost(), chosen.getPort(), instances.size());
        }
        return new DefaultResponse(chosen);
    }

    private ServiceInstance roundRobin(List<ServiceInstance> instances) {
        int pos = Math.abs(position.incrementAndGet());
        return instances.get(pos % instances.size());
    }

    private static List<ServiceInstance> filterByHost(List<ServiceInstance> instances, String host) {
        if (instances == null || instances.isEmpty() || !StringUtils.hasText(host)) {
            return List.of();
        }
        List<ServiceInstance> out = new ArrayList<>();
        for (ServiceInstance si : instances) {
            if (si == null) {
                continue;
            }
            if (host.equals(si.getHost())) {
                out.add(si);
            }
        }
        return out;
    }

    private static Set<String> resolveLocalIps(PreferLocalLoadBalancerProperties props) {
        Set<String> ips = new HashSet<>();

        if (props != null && props.getLocalIps() != null) {
            for (String ip : props.getLocalIps()) {
                if (StringUtils.hasText(ip)) {
                    ips.add(ip.trim());
                }
            }
        }

        // 手工指定优先级最高，避免探测误差
        if (!ips.isEmpty()) {
            return ips;
        }

        if (props == null || !props.isDetectLocalIps()) {
            return ips;
        }

        try {
            Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
            if (nis == null) {
                return ips;
            }
            while (nis.hasMoreElements()) {
                NetworkInterface ni = nis.nextElement();
                if (ni == null) {
                    continue;
                }
                if (!ni.isUp() || ni.isLoopback() || ni.isVirtual()) {
                    continue;
                }
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    if (addr == null) {
                        continue;
                    }
                    if (addr.isLoopbackAddress() || addr.isLinkLocalAddress()) {
                        continue;
                    }
                    if (addr instanceof Inet4Address) {
                        ips.add(addr.getHostAddress());
                    }
                }
            }
        } catch (Exception e) {
            log.warn("探测本机 IP 失败，可通过 boot.cloud.lb.prefer-local.local-ips 手工指定，msg={}", e.getMessage());
        }

        return ips;
    }

    private static String resolveCallerIpFromRequest(Request request, PreferLocalLoadBalancerProperties props) {
        if (request == null || props == null || !props.isPreferCallerIp()) {
            return null;
        }
        if (!(request.getContext() instanceof RequestDataContext)) {
            return null;
        }

        RequestDataContext rdc = (RequestDataContext) request.getContext();
        Object clientReq = rdc.getClientRequest();
        if (!(clientReq instanceof RequestData)) {
            return null;
        }
        RequestData rd = (RequestData) clientReq;

        // 1) 先从指定 header 取值
        String headerName = props.getCallerIpHeaderName();
        if (StringUtils.hasText(headerName)) {
            List<String> v = rd.getHeaders().get(headerName);
            if (v != null && !v.isEmpty() && StringUtils.hasText(v.get(0))) {
                return v.get(0).trim();
            }
        }

        // 2) 可选：信任 forwarded headers
        if (props.isTrustForwardedHeaders()) {
            List<String> xff = rd.getHeaders().get("X-Forwarded-For");
            if (xff != null && !xff.isEmpty()) {
                String first = firstIpFromXff(xff.get(0));
                if (StringUtils.hasText(first)) {
                    return first.trim();
                }
            }
            List<String> xReal = rd.getHeaders().get("X-Real-IP");
            if (xReal != null && !xReal.isEmpty() && StringUtils.hasText(xReal.get(0))) {
                return xReal.get(0).trim();
            }
        }

        return null;
    }

    private static String firstIpFromXff(String xff) {
        if (!StringUtils.hasText(xff)) {
            return null;
        }
        String v = xff.trim();
        int idx = v.indexOf(',');
        String first = idx > 0 ? v.substring(0, idx) : v;
        return first.trim();
    }
}
