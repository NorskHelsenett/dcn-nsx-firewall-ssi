import {
  FortiOSDriver,
  FortiOSSystemVDOM,
  isDevMode,
  NAMNsxIntegrator,
} from "@norskhelsenett/zeniki";
import {
  FortiOSAddresses,
  FortiOSAddresses6,
  FortiOSAddressGrps,
  FortiOSAddressGrps6,
} from "../ssi.utils.ts";
import logger from "../loggers/logger.ts";

export const deployIPv4 = async (
  integrator: NAMNsxIntegrator,
  firewall: FortiOSDriver,
  vdom: FortiOSSystemVDOM,
  fortiOSIPv4Groups: FortiOSAddressGrps,
  fortiOSIPv4Addresses: FortiOSAddresses,
) => {
  try {
    // Fetch existing addresses and address groups from Fortigate
    const fgIPv4Addresses = await firewall.address.getAddresses({
      vdom: vdom.name,
    });

    const fgIPv4Groups = await firewall.addrgrp.getAddressGroups({
      vdom: vdom.name,
    });

    // Find missing addresses and groups
    const missingAddresses = Object.values(fortiOSIPv4Addresses).filter(
      (address) =>
        !fgIPv4Addresses.results.some(
          (fgAddress) => fgAddress.name === address.name,
        ),
    );

    const missingGroups = Object.values(fortiOSIPv4Groups).filter(
      (group) =>
        !fgIPv4Groups.results.some((fgGroup) => fgGroup.name === group.name),
    );

    // Create missing addresses and groups on Fortigate
    for (const address of missingAddresses) {
      await firewall.address.addAddress(address, { vdom: vdom.name }).then(
        () => {
          logger.info(
            `nsx-firewall-ssi: Created IPv4 address '${address.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'.`,
          );
        },
      ).catch((error: Error) => {
        logger.error(
          `nsx-firewall-ssi: Failed to create IPv4 address '${address.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'`,
          {
            component: "fortios.service",
            method: "deployIPV4ToVdom",
            error: isDevMode() ? error : error?.message,
          },
        );
      });
    }

    for (const group of missingGroups) {
      await firewall.addrgrp.addAddressGroup(group, { vdom: vdom.name }).then(
        () => {
          logger.info(
            `nsx-firewall-ssi: Created IPv4 address group '${group.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'.`,
          );
        },
      ).catch((error: Error) => {
        logger.error(
          `nsx-firewall-ssi: Failed to create IPv4 address group '${group.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'`,
          {
            component: "fortios.service",
            method: "deployIPV4ToVdom",
            error: isDevMode() ? error : error?.message,
          },
        );
      });
    }

    // Update group if the members have changed
    for (const group of Object.values(fortiOSIPv4Groups)) {
      const existingGroup = fgIPv4Groups.results.find(
        (fgGroup) => fgGroup.name === group.name,
      );

      if (existingGroup) {
        const existingMembers = existingGroup.member?.map((m) =>
          m.name
        ).sort() || [];
        const newMembers = group.member.map((m) => m.name).sort();

        const hasChanged =
          JSON.stringify(existingMembers) !== JSON.stringify(newMembers);

        if (hasChanged) {
          console.log(`  - Updating group: ${group.name}`);
          await firewall.addrgrp.updateAddressGroup(group.name, group, {
            vdom: vdom.name,
          }).then(
            () => {
              logger.info(
                `nsx-firewall-ssi: Updated IPv4 address group '${group.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'.`,
              );
            },
          ).catch((error: Error) => {
            logger.error(
              `nsx-firewall-ssi: Failed to update IPv4 address group '${group.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'`,
              {
                component: "fortios.service",
                method: "deployIPV4ToVdom",
                error: isDevMode() ? error : error?.message,
              },
            );
          });
        }
      }
    }
  } catch (error) {
    throw error;
  }
};

export const deployIPv6 = async (
  firewall: FortiOSDriver,
  vdom: FortiOSSystemVDOM,
  fortiOSIPv6Groups: FortiOSAddressGrps6,
  fortiOSIPv6Addresses: FortiOSAddresses6,
) => {
  try {
    // Fetch existing addresses and address groups from Fortigate
    const fgIPv6Addresses = await firewall.address6.getAddresses6({
      vdom: vdom.name,
    });

    const fgIPv6Groups = await firewall.addrgrp6.getAddressGroups6({
      vdom: vdom.name,
    });

    // Find missing addresses and groups
    const missingAddresses = Object.values(fortiOSIPv6Addresses).filter(
      (address) =>
        !fgIPv6Addresses.results.some(
          (fgAddress) => fgAddress.name === address.name,
        ),
    );

    const missingGroups = Object.values(fortiOSIPv6Groups).filter(
      (group) =>
        !fgIPv6Groups.results.some((fgGroup) => fgGroup.name === group.name),
    );
    // Create missing addresses and groups on Fortigate
    for (const address of missingAddresses) {
      await firewall.address6.addAddress6(address, { vdom: vdom.name });
    }

    for (const group of missingGroups) {
      await firewall.addrgrp6.addAddressGroup6(group, { vdom: vdom.name });
    }
    // Update group if the members have changed
    for (const group of Object.values(fortiOSIPv6Groups)) {
      const existingGroup = fgIPv6Groups.results.find(
        (fgGroup) => fgGroup.name === group.name,
      );

      if (existingGroup) {
        const existingMembers = existingGroup.member?.map((m) =>
          m.name
        ).sort() || [];
        const newMembers = group.member.map((m) => m.name).sort();

        const hasChanged =
          JSON.stringify(existingMembers) !== JSON.stringify(newMembers);

        if (hasChanged) {
          console.log(`  - Updating group: ${group.name}`);
          await firewall.addrgrp6.updateAddressGroup6(group.name, group, {
            vdom: vdom.name,
          });
        }
      }
    }
  } catch (error) {
    throw error;
  }
};
