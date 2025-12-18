import {
  FortiOSFirewallAddress,
  FortiOSFirewallAddress6,
  FortiOSFirewallAddress6Type,
  FortiOSFirewallAddressType,
  FortiOSFirewallAddrGrp,
  FortiOSFirewallAddrGrp6,
  NAMAPIEndpoint,
  VMwareNSXDriver,
  VMwareNSXGroup,
  VMwareNSXVirtualMachine,
  VMwareNSXVirtualNetworkInterface,
} from "@norskhelsenett/zeniki";
import ipaddr from "ipaddr.js";
import { createHash } from "node:crypto";
import { IPv4CidrRange, Validator } from "ip-num";
const SSI_NAME = Deno.env.get("SSI_NAME") ?? "SSI_NAME_MISSING";
import packageInfo from "../deno.json" with { type: "json" };
const USER_AGENT = `${SSI_NAME}/${packageInfo.version}`;

export type FortiOSAddressGrps = Record<string, FortiOSFirewallAddrGrp>;
export type FortiOSAddresses = Record<string, FortiOSFirewallAddress>;
export type FortiOSAddressGrps6 = Record<string, FortiOSFirewallAddrGrp6>;
export type FortiOSAddresses6 = Record<string, FortiOSFirewallAddress6>;

export const createIPv4Address = (
  ip: string,
  addressName: string,
  isHashed = false,
): FortiOSFirewallAddress | null => {
  if (Validator.isValidIPv4String(ip)[0]) {
    return {
      name: addressName,
      type: FortiOSFirewallAddressType.IP_Mask,
      subnet: `${ip} 255.255.255.255`,
      comment: isHashed ? "Hashed address name due to length" : "",
    };
  } else if (Validator.isValidIPv4CidrNotation(ip)[0]) {
    const subnet = ip.split("/")[0];
    const subnetMask = IPv4CidrRange.fromCidr(ip)
      .getPrefix()
      .toMask()
      .toString();
    return {
      name: addressName,
      type: FortiOSFirewallAddressType.IP_Mask,
      subnet: `${subnet} ${subnetMask}`,
      comment: isHashed ? "Hashed address name due to length" : "",
    };
  } else if (Validator.isValidIPv4RangeString(ip)[0]) {
    const [start, end] = ip.split("-");
    return {
      name: addressName,
      type: FortiOSFirewallAddressType.IP_Range,
      "start-ip": start,
      "end-ip": end,
      comment: isHashed ? "Hashed address name due to length" : "",
    };
  }
  return null;
};

export const createIPv6Address = (
  ip: string,
  addressName: string,
  isHashed = false,
): FortiOSFirewallAddress6 | null => {
  if (Validator.isValidIPv6CidrNotation(ip)[0]) {
    return {
      name: addressName,
      type: FortiOSFirewallAddress6Type.IP_Prefix,
      ip6: ip,
      comment: isHashed ? "Hashed address name due to length" : "",
    };
  } else if (Validator.isValidIPv6RangeString(ip)[0]) {
    const [start, end] = ip.split("-");
    return {
      name: addressName,
      type: FortiOSFirewallAddress6Type.IP_Range,
      "start-ip": start,
      "end-ip": end,
      comment: isHashed ? "Hashed address name due to length" : "",
    };
  }
  return null;
};

export const filterVMsByTag = (
  vms: VMwareNSXVirtualMachine[],
  scope: string,
  tagName: string,
): VMwareNSXVirtualMachine[] => {
  return vms.filter((vm) =>
    vm.tags?.some((t) => t.scope === scope && t.tag === tagName)
  );
};

export const filterGroupsByTag = (
  groups: VMwareNSXGroup[],
  scope: string,
  tagName: string,
): VMwareNSXGroup[] => {
  return groups.filter((group) =>
    group.tags?.some((t) => t.scope === scope && t.tag === tagName)
  );
};

export const getVmIpAddresses = async (
  nsx: VMwareNSXDriver,
  vmId: string,
): Promise<string[]> => {
  const vifs = await nsx.virtualInterfaces.getVirtualInterfaces({
    owner_vm_id: vmId,
  });
  return extractIpAddresses(vifs.results);
};

function extractIpAddresses(vifs: VMwareNSXVirtualNetworkInterface[]) {
  const ips = vifs
    .flatMap((vif) => vif.ip_address_info ?? [])
    .flatMap((info) => info.ip_addresses ?? []);

  return [...new Set(ips)].sort();
}

export const isGlobalManagerPath = (path: string): boolean => {
  return (
    path.startsWith("/global-infra/domains/") ||
    path.startsWith("/global-manager/api/v1/")
  );
};

/**
 * Filters out link-local IP addresses from an array of address strings.
 *
 * Link-local addresses are IP addresses that are valid only for communications within
 * the network segment or broadcast domain that the host is connected to.
 *
 * @param addresses - An array of IP address strings. Addresses may include CIDR notation (e.g., "192.168.1.1/24") or IP ranges (e.g., "192.168.1.1-192.168.1.10").
 * @returns A filtered array containing only non-link-local addresses and address ranges (identified by containing "-").
 * @throws Re-throws any error encountered during IP address parsing.
 *
 * @remarks
 * The function handles three cases:
 * - Addresses containing a hyphen "-" are assumed to be ranges and are kept
 * - Addresses with CIDR notation (containing "/") have the network portion extracted before checking
 * - Single IP addresses are checked directly
 */
export const removeLinkLocalAddresses = (addresses: string[]) => {
  try {
    return addresses.filter((address) => {
      if (address.includes("-")) {
        return address;
      } else if (ipaddr.parse(address.split("/")[0]).range() !== "linkLocal") {
        return address;
      } else if (ipaddr.parse(address).range() !== "linkLocal") {
        return address;
      }
    });
  } catch (error) {
    throw error;
  }
};

export const createNsxClient = (endpoint: NAMAPIEndpoint) => {
  const username = endpoint?.user + "";
  const password = endpoint?.pass + "";
  const authString = `${username}:${password}`;
  const encodedAuth = btoa(authString);

  return new VMwareNSXDriver({
    baseURL: endpoint?.url?.replace("/api/v1", ""),
    headers: {
      "User-Agent": USER_AGENT,
      "Content-Type": "application/json",
      Authorization: `Basic ${encodedAuth}`,
    },
    // TODO: Figure out proper timeout, signal: AbortSignal.timeout(REQUEST_TIMEOUT),
  });
};

/**
 * Generates an MD5 hash of an IP address.
 *
 * @param address - The IP address string to be hashed
 * @returns The MD5 hash of the input address as a hexadecimal string
 *
 * @example
 * ```typescript
 * const hashedIp = hashIpAddress("192.168.1.1");
 * // Returns: "c12968c9f5d8d8e5d8c5c8e5d8c5c8e5" (example hash)
 * ```
 */
export const hashIpAddress = (address: string) => {
  const hash = createHash("md5").update(address).digest("hex");
  return hash;
};

/**
 * Merges address objects from a source record into a target record.
 * Only adds entries from source that don't already exist in target (non-destructive merge).
 *
 * @template T - Type of objects being merged, must have a 'name' property of type string
 * @param target - The target record to merge into. This object will be modified in place.
 * @param source - The source record to merge from. Entries from this record are added to target if they don't already exist.
 * @returns The modified target record containing all original entries plus non-conflicting entries from source
 *
 * @example
 * ```typescript
 * const target = { 'obj1': { name: 'Object 1' } };
 * const source = { 'obj2': { name: 'Object 2' }, 'obj1': { name: 'Duplicate' } };
 * const result = mergeAddressObjects(target, source);
 * // result will be { 'obj1': { name: 'Object 1' }, 'obj2': { name: 'Object 2' } }
 * ```
 */
export const mergeAddressObjects = <T extends { name: string }>(
  target: Record<string, T>,
  source: Record<string, T>,
): Record<string, T> => {
  for (const [key, value] of Object.entries(source)) {
    if (!target[key]) {
      target[key] = value;
    }
  }
  return target;
};

/**
 * Merges two records of group objects, combining their members by name.
 *
 * @template G - A type that extends an object with a `name` string property and a `member` array of objects with `name` properties
 * @param target - The target record to merge into. This object will be modified in place.
 * @param incoming - The incoming record to merge from
 * @returns The merged record with combined groups and deduplicated members
 *
 * @remarks
 * - If a group exists only in `incoming`, it is added to `target` with a shallow copy of its members
 * - If a group exists in both records, their properties are merged and members are deduplicated by name
 */
export const mergeGroupObjects = <
  G extends {
    name: string;
    member: { name: string }[];
  },
>(
  target: Record<string, G>,
  incoming: Record<string, G>,
): Record<string, G> => {
  for (const [key, incGroup] of Object.entries(incoming)) {
    const existing = target[key];

    if (!existing) {
      target[key] = {
        ...incGroup,
        member: [...(incGroup.member ?? [])],
      } as G;
      continue;
    }

    const mergedMembersByName = new Map<string, { name: string }>();

    for (const m of existing.member ?? []) mergedMembersByName.set(m.name, m);
    for (const m of incGroup.member ?? []) mergedMembersByName.set(m.name, m);

    target[key] = {
      ...(existing as object),
      ...(incGroup as object),
      member: [...mergedMembersByName.values()],
    } as G;
  }

  return target;
};
