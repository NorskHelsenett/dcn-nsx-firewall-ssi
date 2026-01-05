/**
 * NSX Service - Manages VMware NSX security groups for IP address management
 * Syncs IP prefixes from NSX to NSX security groups
 */

import {
  FortiOSFirewallAddress6Type,
  FortiOSFirewallAddressType,
  HTTPError,
  isDevMode,
  NAMAPIEndpoint,
  NAMNsxIntegrator,
  NetboxTag,
  VMwareNSXDriver,
  VMwareNSXEnforcementPoint,
  VMwareNSXGroup,
  VMwareNSXResponse,
  VMwareNSXSite,
  VMwareNSXTag,
  VMwareNSXVirtualMachine,
  VMwareNSXVirtualNetworkInterface,
} from "@norskhelsenett/zeniki";

import {
  createIPv4Address,
  createIPv6Address,
  filterGroupsByTag,
  filterVMsByTag,
  FortiOSAddresses,
  FortiOSAddresses6,
  FortiOSAddressGrps,
  FortiOSAddressGrps6,
  getVmIpAddresses,
  hashIpAddress,
  removeLinkLocalAddresses,
} from "../ssi.utils.ts";
import ipaddr from "ipaddr.js";
import { Validator } from "ip-num";
import logger from "../loggers/logger.ts";

export const getVMTagsGroupsAndMembers = async (
  nsx: VMwareNSXDriver,
  integrator: NAMNsxIntegrator,
  manager: NAMAPIEndpoint,
) => {
  try {
    const fortiOSIPv4Groups: FortiOSAddressGrps = {};
    const fortiOSIPv4Addresses: FortiOSAddresses = {};
    const fortiOSIPv6Groups: FortiOSAddressGrps6 = {};
    const fortiOSIPv6Addresses: FortiOSAddresses6 = {};
    const vmTags = integrator.vm_tags as NetboxTag[];
    const scope = integrator.scope;
    const scopedVirtualMachines: VMwareNSXVirtualMachine[] =
      (await nsx.search.query<
        VMwareNSXVirtualMachine
      >(
        {
          query:
            `resource_type:VirtualMachine AND tags.scope:${scope} AND power_state:VM_RUNNING`,
        },
        false,
      ).catch(
        (error: HTTPError) => {
          logger.warning(
            `nsx-firewall-ssi: Could not retrieve prefixes from NSX ${nsx.getHostname()} due to ${error.message} `,
            {
              component: "ssi.worker",
              method: "work",
              error: isDevMode() ? error : error.message,
            },
          );
          return;
        },
      ) as VMwareNSXResponse<VMwareNSXVirtualMachine>)?.results;

    for (const tag of vmTags) {
      if (isDevMode()) {
        logger.debug(
          `nsx-firewall-ssi:      - Processing vm tag ${tag.name}.`,
        );
      }
      const ipv4GroupName = `grp_${manager.name}_${scope}_${tag.name}`;
      const ipv6GroupName = `grp6_${manager.name}_${scope}_${tag.name}`;

      if (!fortiOSIPv4Groups[ipv4GroupName]) {
        fortiOSIPv4Groups[ipv4GroupName] = {
          name: ipv4GroupName,
          comment: "Managed by NAM",
          color: 3,
          member: [],
        };
      }
      if (!fortiOSIPv6Groups[ipv6GroupName]) {
        fortiOSIPv6Groups[ipv6GroupName] = {
          name: ipv6GroupName,
          comment: "Managed by NAM",
          color: 3,
          member: [],
        };
      }

      const taggedVirtualMachines = filterVMsByTag(
        scopedVirtualMachines,
        scope,
        tag.name,
      );

      for (const vm of taggedVirtualMachines) {
        const IPAddresses = await getVmIpAddresses(nsx, vm.external_id);
        const noneLinkLocalIPAddresses = removeLinkLocalAddresses(IPAddresses);

        const ipv4Addresses: string[] = [];
        const ipv6Addresses: string[] = [];

        for (const ip of noneLinkLocalIPAddresses) {
          const version = ipaddr.parse(ip).kind();
          if (version === "ipv4") ipv4Addresses.push(ip);
          else if (version === "ipv6") ipv6Addresses.push(ip);
        }

        if (ipv4Addresses.length > 0) {
          for (const [index, ip] of ipv4Addresses.entries()) {
            const ipv4AddressName = index === 0
              ? `nsx_${vm.display_name}`
              : `nsx_${vm.display_name}_${ip}`;

            if (!fortiOSIPv4Addresses[ipv4AddressName]) {
              fortiOSIPv4Addresses[ipv4AddressName] = {
                name: ipv4AddressName,
                type: FortiOSFirewallAddressType.IP_Mask,
                subnet: `${ip} 255.255.255.255`,
                color: 0,
                comment: "",
              };
            }

            fortiOSIPv4Groups[ipv4GroupName].member.push({
              name: ipv4AddressName,
            });
          }
        }

        if (ipv6Addresses.length > 0) {
          for (const [index, ip] of ipv6Addresses.entries()) {
            const ipv6AddressName = index === 0
              ? `nsx6_${vm.display_name}`
              : `nsx6_${vm.display_name}_${ip}`;

            if (!fortiOSIPv6Addresses[ipv6AddressName]) {
              fortiOSIPv6Addresses[ipv6AddressName] = {
                name: ipv6AddressName,
                type: FortiOSFirewallAddress6Type.IP_Prefix,
                ip6: `${ip}/128`,
                color: 0,
                comment: "",
              };
            }

            fortiOSIPv6Groups[ipv6GroupName].member.push({
              name: ipv6AddressName,
            });
          }
        }
      }
    }

    return {
      fortiOSIPv4Groups,
      fortiOSIPv4Addresses,
      fortiOSIPv6Groups,
      fortiOSIPv6Addresses,
    };
  } catch (error) {
    throw error;
  }
};

export const getGroupTagsGroupsAndMembers = async (
  nsx: VMwareNSXDriver,
  integrator: NAMNsxIntegrator,
  manager: NAMAPIEndpoint,
) => {
  try {
    const fortiOSIPv4Groups: FortiOSAddressGrps = {};
    const fortiOSIPv4Addresses: FortiOSAddresses = {};
    const fortiOSIPv6Groups: FortiOSAddressGrps6 = {};
    const fortiOSIPv6Addresses: FortiOSAddresses6 = {};
    const scope = integrator.scope;
    const gm = manager.type === "global";
    const resourceType = gm ? "Group" : "NSGroup";
    const groupTags = integrator.group_tags as NetboxTag[];

    const scopedGroups: VMwareNSXGroup[] =
      (await nsx.search.query<VMwareNSXGroup>(
        {
          query: `resource_type:${resourceType} AND tags.scope:${scope}`,
        },
        gm,
      ).catch(
        (error: HTTPError) => {
          logger.warning(
            `nsx-firewall-ssi: Could not retrieve groups from NSX ${nsx.getHostname()} due to ${error.message} `,
            {
              component: "ssi.worker",
              method: "work",
              error: isDevMode() ? error : error.message,
            },
          );
          return;
        },
      ) as VMwareNSXResponse<VMwareNSXGroup>)?.results;

    if (isDevMode()) {
      logger.debug(
        `nsx-firewall-ssi:   -- Processing group tags from local manager ${manager.name}.`,
      );
    }
    for (const tag of groupTags) {
      if (isDevMode()) {
        logger.debug(
          `nsx-firewall-ssi:      - Processing group tag ${tag.name}.`,
        );
      }
      const ipv4GroupName = `grp_${manager.name}_${scope}_${tag.name}`;
      const ipv6GroupName = `grp6_${manager.name}_${scope}_${tag.name}`;

      const taggedGroups = filterGroupsByTag(
        scopedGroups,
        scope,
        tag.name,
      );

      for (const group of taggedGroups) {
        if (!fortiOSIPv4Groups[ipv4GroupName]) {
          fortiOSIPv4Groups[ipv4GroupName] = {
            name: ipv4GroupName,
            comment: "Managed by NAM",
            color: 3,
            member: [],
          };
        }
        if (!fortiOSIPv6Groups[ipv6GroupName]) {
          fortiOSIPv6Groups[ipv6GroupName] = {
            name: ipv6GroupName,
            comment: "Managed by NAM",
            color: 3,
            member: [],
          };
        }

        const policyPath = manager.type === "global"
          ? group.path
          : group.tags?.find(
            (tag: VMwareNSXTag) => tag.scope === "policyPath",
          )?.tag;

        // Get the ip addresses from the nsx security group
        let groupIpAddresses: string[] = [];
        let groupVifAddresses: string[] = [];

        if (manager.type === "global") {
          if (group.expression) {
            for (const expression of group.expression) {
              if (expression.ip_addresses) {
                groupIpAddresses = groupIpAddresses.concat(
                  expression.ip_addresses,
                );
              }
            }
          }
          const globalManagerSites: VMwareNSXSite[] = (
            await nsx.sites.getSites()
          )?.results;

          const gmEnforcementPoints: VMwareNSXEnforcementPoint[] = [];

          for (const site of globalManagerSites) {
            const siteEnforcementPoints = await nsx.sites
              .getSiteEnforcementPoints(site.id!);
            gmEnforcementPoints.push(...siteEnforcementPoints.results);
          }

          const enforcementPointIPAddresses =
            await getGlobalManagerEnforcementPointGroupMembers(
              nsx,
              group,
              gmEnforcementPoints,
            );

          const noneLinkLocalEPIPAddresses = removeLinkLocalAddresses(
            enforcementPointIPAddresses,
          );

          // Remove duplicates
          groupIpAddresses = [...new Set(noneLinkLocalEPIPAddresses)];
        } else {
          const ipAddressUrl =
            `/policy/api/v1${policyPath}/members/ip-addresses`;
          const groupMemberIps: string[] = (await nsx.getByUrl<
            VMwareNSXResponse<string>
          >(
            ipAddressUrl,
          ).catch(
            (error: HTTPError) => {
              logger.warning(
                `nsx-firewall-ssi: Could not retrieve group member ip addresses from NSX for group ${group.display_name} ${nsx?.getHostname()} due to ${error.message} `,
                {
                  component: "ssi.worker",
                  method: "work",
                  error: isDevMode() ? error : error.message,
                },
              );
              return;
            },
          ) as VMwareNSXResponse<string>)?.results;

          groupIpAddresses = groupIpAddresses.concat(groupMemberIps);

          const vifsUrl = `/policy/api/v1${policyPath}/members/vifs`;
          const groupMemberVifs: VMwareNSXVirtualNetworkInterface[] = (await nsx
            .getByUrl<
              VMwareNSXResponse<VMwareNSXVirtualNetworkInterface>
            >(
              vifsUrl,
            ).catch(
              (error: HTTPError) => {
                logger.warning(
                  `nsx-firewall-ssi: Could not retrieve group member virtual interfaces from NSX for group ${group.display_name} ${nsx?.getHostname()} due to ${error.message} `,
                  {
                    component: "ssi.worker",
                    method: "work",
                    error: isDevMode() ? error : error.message,
                  },
                );
                return;
              },
            ) as VMwareNSXResponse<VMwareNSXVirtualNetworkInterface>)?.results;

          for (const vif of groupMemberVifs) {
            if (vif.ip_address_info && vif.ip_address_info.length > 0) {
              for (const info of vif.ip_address_info) {
                groupVifAddresses = groupVifAddresses.concat(
                  info.ip_addresses || [],
                );
              }
            }
          }
        }

        // Process IP addresses
        for (const ip of groupIpAddresses) {
          let normalizedIp = ip;
          if (ip.includes("/") && ip.split("/")[1] === "32") {
            normalizedIp = ip.split("/")[0];
          }

          // Filter out vif addresses
          if (
            groupVifAddresses.some((vifIp: string) => {
              return vifIp === normalizedIp;
            })
          ) {
            continue;
          }

          const isIPv4 = Validator.isValidIPv4String(normalizedIp)[0] ||
            Validator.isValidIPv4CidrNotation(normalizedIp)[0] ||
            Validator.isValidIPv4RangeString(normalizedIp)[0];

          const isIPv6 = Validator.isValidIPv6String(normalizedIp)[0] ||
            Validator.isValidIPv6CidrNotation(normalizedIp)[0] ||
            Validator.isValidIPv6RangeString(normalizedIp)[0];

          if (isIPv4) {
            let ipv4AddressName =
              `nsx_${manager.name}_${group.display_name}_${normalizedIp}${
                Validator.isValidIPv4String(normalizedIp)[0] ? "/32" : ""
              }`;

            // Maximum length of an address object in Fortigate is 79 characters
            // so hash the ip if its to long
            if (ipv4AddressName.length > 79) {
              ipv4AddressName = `nsx_${manager.name}_${group.display_name}_${
                hashIpAddress(normalizedIp)
              }`;
            }

            const address = createIPv4Address(
              normalizedIp,
              ipv4AddressName,
              ipv4AddressName.length > 79,
            );

            if (!fortiOSIPv4Addresses[ipv4AddressName]) {
              if (address) {
                fortiOSIPv4Addresses[ipv4AddressName] = address;
              }
            }

            if (
              !fortiOSIPv4Groups[ipv4GroupName].member.some(
                (member) => member.name === ipv4AddressName,
              )
            ) {
              fortiOSIPv4Groups[ipv4GroupName].member.push({
                name: ipv4AddressName,
              });
            }
          } else if (isIPv6) {
            let ipv6AddressName =
              `nsx6_${manager.name}_${group.display_name}_${normalizedIp}`;

            // Maximum length of an address object in Fortigate is 79 characters
            // so hash the ip if its to long
            if (ipv6AddressName.length > 79) {
              ipv6AddressName = `nsx6_${manager.name}_${
                hashIpAddress(normalizedIp)
              }`;
            }

            if (!fortiOSIPv6Addresses[ipv6AddressName]) {
              const address = createIPv6Address(
                normalizedIp,
                ipv6AddressName,
                ipv6AddressName.length > 79,
              );
              if (address) {
                fortiOSIPv6Addresses[ipv6AddressName] = address;
              }
            }

            if (
              !fortiOSIPv6Groups[ipv6GroupName].member.some(
                (member) => member.name === ipv6AddressName,
              )
            ) {
              fortiOSIPv6Groups[ipv6GroupName].member.push({
                name: ipv6AddressName,
              });
            }
          }
        }
      }
    }
    return {
      fortiOSIPv4Groups,
      fortiOSIPv4Addresses,
      fortiOSIPv6Groups,
      fortiOSIPv6Addresses,
    };
  } catch (error) {
    throw error;
  }
};

const getGlobalManagerEnforcementPointGroupMembers = async (
  nsx: VMwareNSXDriver,
  group: VMwareNSXGroup,
  enforcementPoints: VMwareNSXEnforcementPoint[],
) => {
  try {
    let ipAddresses: string[] = [];

    for (const enforcementPoint of enforcementPoints) {
      const ipAddressesFromEP = await nsx.groups.getGroupMemberIPAddresses(
        group.id!,
        {
          enforcement_point_path: enforcementPoint.path,
        },
        "default",
        true,
      );

      if (ipAddressesFromEP) {
        ipAddresses = ipAddresses.concat(ipAddressesFromEP.results!);
      }
    }

    return ipAddresses;
  } catch (error) {
    throw error;
  }
};
