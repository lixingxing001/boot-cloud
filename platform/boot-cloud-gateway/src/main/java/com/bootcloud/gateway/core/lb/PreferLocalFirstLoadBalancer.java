package com.bootcloud.gateway.core.lb;

import com.bootcloud.gateway.config.GatewayPreferLocalLoadBalancerProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.RequestData;
import org.springframework.cloud.client.loadbalancer.RequestDataContext;
import org.springframework.cloud.client.loadbalancer.Request;
import org.springframework.cloud.client.loadbalancer.Response;
import org.springframework.cloud.client.loadbalancer.DefaultResponse;
import org.springframework.cloud.client.loadbalancer.EmptyResponse;
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
 *   <li>该策略对所有 lb:// 服务生效。</li>
 * </ul>
 */
@Slf4j
public class PreferLocalFirstLoadBalancer implements ReactorServiceInstanceLoadBalancer {

    private final ObjectProvider<ServiceInstanceListSupplier> supplierProvider;
    private final String serviceId;
    private final GatewayPreferLocalLoadBalancerProperties props;
    private final AtomicInteger position;
    private final Set<String> localIpSet;

    public PreferLocalFirstLoadBalancer(
            ObjectProvider<ServiceInstanceListSupplier> supplierProvider,
            String serviceId,
            GatewayPreferLocalLoadBalancerProperties props
    ) {
        this.supplierProvider = supplierProvider;
        this.serviceId = serviceId;
        this.props = props;
        this.position = new AtomicInteger(0);
        this.localIpSet = Collections.unmodifiableSet(resolveLocalIps(props));

        if (log.isInfoEnabled()) {
            log.info("本机优先负载均衡已初始化：serviceId={}, enabled={}, localIps={}",
                    serviceId, props.isEnabled(), this.localIpSet);
        }
    }

    @Override
    public Mono<Response<ServiceInstance>> choose(Request request) {
        ServiceInstanceListSupplier supplier = supplierProvider == null ? null : supplierProvider.getIfAvailable();
        if (supplier == null) {
            log.warn("LoadBalancer 未获取到实例提供者：serviceId={}", serviceId);
            return Mono.just(new EmptyResponse());
        }
        String callerIp = resolveCallerIpFromRequest(request);
        return supplier.get(request).next().map(instances -> chooseFromList(instances, callerIp));
    }

    private Response<ServiceInstance> chooseFromList(List<ServiceInstance> instances, String callerIp) {
        if (instances == null || instances.isEmpty()) {
            log.warn("LoadBalancer 未发现可用实例：serviceId={}", serviceId);
            return new EmptyResponse();
        }

        // 1) 优先按调用方 IP 选实例（可实现 调用方优先命中同主机实例）
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
                        serviceId,
                        chosen.getHost(),
                        chosen.getPort(),
                        local.size(),
                        instances.size());
            }
            return new DefaultResponse(chosen);
        }

        if (log.isDebugEnabled()) {
            log.debug("LoadBalancer 未发现本机实例，回退到非本机实例：serviceId={}, total={}", serviceId, instances.size());
        }
        return new DefaultResponse(roundRobin(instances));
    }

    private static List<ServiceInstance> filterByHost(List<ServiceInstance> instances, String ip) {
        if (!StringUtils.hasText(ip) || instances == null || instances.isEmpty()) {
            return List.of();
        }
        List<ServiceInstance> out = new ArrayList<>();
        for (ServiceInstance si : instances) {
            if (si == null) {
                continue;
            }
            String host = si.getHost();
            if (StringUtils.hasText(host) && ip.equals(host.trim())) {
                out.add(si);
            }
        }
        return out;
    }

    private String resolveCallerIpFromRequest(Request request) {
        if (request == null || !props.isEnabled() || !props.isPreferCallerIp()) {
            return null;
        }
        String headerName = props.getCallerIpHeaderName();
        if (!StringUtils.hasText(headerName)) {
            return null;
        }
        try {
            Object ctx = request.getContext();
            if (!(ctx instanceof RequestDataContext rdc)) {
                return null;
            }
            RequestData rd = rdc.getClientRequest();
            if (rd == null || rd.getHeaders() == null) {
                return null;
            }
            String ip = rd.getHeaders().getFirst(headerName);
            return StringUtils.hasText(ip) ? ip.trim() : null;
        } catch (Exception e) {
            log.debug("解析调用方 IP 失败：serviceId={}，msg={}", serviceId, e.getMessage());
            return null;
        }
    }

    private ServiceInstance roundRobin(List<ServiceInstance> list) {
        int pos = position.incrementAndGet();
        int idx = Math.floorMod(pos, list.size());
        return list.get(idx);
    }

    private static Set<String> resolveLocalIps(GatewayPreferLocalLoadBalancerProperties props) {
        Set<String> set = new HashSet<>();
        if (props != null && props.getLocalIps() != null) {
            for (String ip : props.getLocalIps()) {
                if (StringUtils.hasText(ip)) {
                    set.add(ip.trim());
                }
            }
        }

        if (props == null || !props.isDetectLocalIps()) {
            return set;
        }

        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces != null && ifaces.hasMoreElements()) {
                NetworkInterface ni = ifaces.nextElement();
                if (ni == null || !ni.isUp() || ni.isLoopback()) {
                    continue;
                }
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs != null && addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress() && !addr.isLinkLocalAddress()) {
                        set.add(addr.getHostAddress());
                    }
                }
            }
        } catch (Exception e) {
            log.warn("探测本机 IP 失败，仍可通过 boot.cloud.gateway.lb.prefer-local.local-ips 手工指定，msg={}", e.getMessage());
        }

        return set;
    }
}
