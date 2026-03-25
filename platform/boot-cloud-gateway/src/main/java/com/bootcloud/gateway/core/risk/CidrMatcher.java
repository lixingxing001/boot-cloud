package com.bootcloud.gateway.core.risk;

import org.springframework.util.StringUtils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * CIDR 匹配工具。
 *
 * <p>说明：</p>
 * <ul>
 *   <li>支持 IPv4 与 IPv6。</li>
 *   <li>规则支持“单 IP”与“CIDR”。</li>
 * </ul>
 */
public final class CidrMatcher {

    private CidrMatcher() {
    }

    /**
     * 解析规则列表，返回可匹配网段。
     */
    public static List<CidrBlock> parseRules(List<String> rules, Consumer<String> invalidRuleConsumer) {
        List<CidrBlock> blocks = new ArrayList<>();
        if (rules == null || rules.isEmpty()) {
            return blocks;
        }
        for (String raw : rules) {
            String rule = raw == null ? "" : raw.trim();
            if (!StringUtils.hasText(rule)) {
                continue;
            }
            try {
                blocks.add(parse(rule));
            } catch (Exception e) {
                if (invalidRuleConsumer != null) {
                    invalidRuleConsumer.accept(rule);
                }
            }
        }
        return blocks;
    }

    /**
     * 判断目标 IP 是否命中任意规则。
     */
    public static boolean matchesAny(String ip, List<CidrBlock> blocks) {
        if (!StringUtils.hasText(ip) || blocks == null || blocks.isEmpty()) {
            return false;
        }
        InetAddress target;
        try {
            target = InetAddress.getByName(ip.trim());
        } catch (Exception e) {
            return false;
        }
        byte[] targetBytes = target.getAddress();
        for (CidrBlock block : blocks) {
            if (block != null && block.matches(targetBytes)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 解析单条规则。
     */
    private static CidrBlock parse(String rule) throws UnknownHostException {
        String[] parts = rule.split("/", 2);
        InetAddress network = InetAddress.getByName(parts[0].trim());
        byte[] networkBytes = network.getAddress();
        int maxBits = networkBytes.length * 8;
        int prefix = maxBits;
        if (parts.length == 2) {
            prefix = Integer.parseInt(parts[1].trim());
            if (prefix < 0 || prefix > maxBits) {
                throw new IllegalArgumentException("invalid prefix");
            }
        }
        return new CidrBlock(networkBytes, prefix);
    }

    public record CidrBlock(byte[] network, int prefixLength) {

        public CidrBlock {
            network = Objects.requireNonNull(network, "network");
        }

        /**
         * 判断目标地址是否落在当前网段。
         */
        public boolean matches(byte[] target) {
            if (target == null || target.length != network.length) {
                return false;
            }
            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;

            for (int i = 0; i < fullBytes; i++) {
                if (network[i] != target[i]) {
                    return false;
                }
            }
            if (remainingBits == 0) {
                return true;
            }
            int mask = 0xFF << (8 - remainingBits);
            return (network[fullBytes] & mask) == (target[fullBytes] & mask);
        }
    }
}

