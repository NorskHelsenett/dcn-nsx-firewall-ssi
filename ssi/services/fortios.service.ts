import {
  FortiOSDriver,
  FortiOSFirewallAddress,
  FortiOSFirewallAddress6,
  FortiOSFirewallAddrGrp,
  FortiOSFirewallAddrGrp6,
  FortiOSResponse,
  FortiOSSystemVDOM,
  HTTPError,
  isDevMode,
  NAMNsxIntegrator,
} from "@norskhelsenett/zeniki";
import {
  address6InUse,
  addressInUse,
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
    const fgIPv4Addresses: FortiOSFirewallAddress[] = (await firewall.address
      .getAddresses({
        vdom: vdom.name,
      }).catch(
        (error: HTTPError) => {
          logger.warning(
            `nsx-firewall-ssi: Could not retrieve ipv4 addresses from Fortigate ${firewall.getHostname()} due to ${error.message} `,
            {
              component: "ssi.worker",
              method: "work",
              error: isDevMode() ? error : error.message,
            },
          );
          return;
        },
      ) as FortiOSResponse<FortiOSFirewallAddress>).results;

    const fgIPv4Groups: FortiOSFirewallAddrGrp[] =
      (await firewall.addrgrp.getAddressGroups({
        vdom: vdom.name,
      }).catch(
        (error: HTTPError) => {
          logger.warning(
            `nsx-firewall-ssi: Could not retrieve ipv4 address groups from Fortigate ${firewall.getHostname()} due to ${error.message} `,
            {
              component: "ssi.worker",
              method: "work",
              error: isDevMode() ? error : error.message,
            },
          );
          return;
        },
      ) as FortiOSResponse<FortiOSFirewallAddrGrp>).results;

    // Find missing addresses and groups
    const missingAddresses = Object.values(fortiOSIPv4Addresses).filter(
      (address) =>
        !fgIPv4Addresses.some(
          (fgAddress) => fgAddress.name === address.name,
        ),
    );

    const missingGroups = Object.values(fortiOSIPv4Groups).filter(
      (group) => !fgIPv4Groups.some((fgGroup) => fgGroup.name === group.name),
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
            method: "deployIPv4",
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
            method: "deployIPv4",
            error: isDevMode() ? error : error?.message,
          },
        );
      });
    }

    // Update group if the members have changed
    for (const group of Object.values(fortiOSIPv4Groups)) {
      const existingGroup = fgIPv4Groups.find(
        (fgGroup) => fgGroup.name === group.name,
      );

      if (existingGroup) {
        //Find members only present in NSX
        const added = group.member?.filter(
          (m) => !existingGroup.member?.some((em) => em.name === m.name),
        );

        //Find members only present in FortiGate
        const removed = existingGroup.member?.filter((m) =>
          !group.member.some((gm) => gm.name === m.name)
        );

        const hasChanged = added.length > 0 || removed.length > 0;

        if (hasChanged) {
          const meta = {
            name: group.name,
            type: "UPDATE",
            src: {
              system: "nsx",
              servers: integrator.managers?.map((m) => m.name),
            },
            dst: {
              system: "fortigate",
              server: firewall.getHostname(),
              options: { vdom: vdom.name },
            },
            changes: {
              added: added.map((a) => a.name),
              removed: removed.map((r) => r.name),
            },
          };
          await firewall.addrgrp.updateAddressGroup(group.name, group, {
            vdom: vdom.name,
          }).then(
            () => {
              logger.info(
                `nsx-firewall-ssi: Updated IPv4 address group '${group.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'.`,
                meta,
              );
            },
          ).catch((error: Error) => {
            logger.error(
              `nsx-firewall-ssi: Failed to update IPv4 address group '${group.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'`,
              {
                component: "fortios.service",
                method: "deployIPv4",
                error: isDevMode() ? error : error?.message,
              },
            );
          });

          if (removed.length > 0) {
            for (const address of removed) {
              const inUse = await addressInUse(
                firewall,
                vdom,
                address,
              );

              if (inUse) {
                logger.info(
                  `nsx-firewall-ssi: IPv4 address '${address.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}' is still in use. Skipping deletion.`,
                );
              } else {
                await firewall.address.deleteAddress(address.name, {
                  vdom: vdom.name,
                }).then(
                  () => {
                    logger.info(
                      `nsx-firewall-ssi: Deleted IPv4 address '${address.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'.`,
                    );
                  },
                ).catch((error: Error) => {
                  logger.error(
                    `nsx-firewall-ssi: Failed to delete IPv4 address '${address.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'`,
                    {
                      component: "fortios.service",
                      method: "deployIPv4",
                      error: isDevMode() ? error : error?.message,
                    },
                  );
                });
              }
            }
          }
        }
      }
    }
  } catch (error) {
    throw error;
  }
};

export const deployIPv6 = async (
  integrator: NAMNsxIntegrator,
  firewall: FortiOSDriver,
  vdom: FortiOSSystemVDOM,
  fortiOSIPv6Groups: FortiOSAddressGrps6,
  fortiOSIPv6Addresses: FortiOSAddresses6,
) => {
  try {
    // Fetch existing addresses and address groups from Fortigate
    const fgIPv6Addresses: FortiOSFirewallAddress6[] = (await firewall.address6
      .getAddresses6({
        vdom: vdom.name,
      }).catch(
        (error: HTTPError) => {
          logger.warning(
            `nsx-firewall-ssi: Could not retrieve ipv6 addresses from Fortigate ${firewall.getHostname()} due to ${error.message} `,
            {
              component: "ssi.worker",
              method: "work",
              error: isDevMode() ? error : error.message,
            },
          );
          return;
        },
      ) as FortiOSResponse<FortiOSFirewallAddress6>).results;

    const fgIPv6Groups: FortiOSFirewallAddrGrp6[] =
      (await firewall.addrgrp6.getAddressGroups6({
        vdom: vdom.name,
      }).catch(
        (error: HTTPError) => {
          logger.warning(
            `nsx-firewall-ssi: Could not retrieve ipv6 address groups from Fortigate ${firewall.getHostname()} due to ${error.message} `,
            {
              component: "ssi.worker",
              method: "work",
              error: isDevMode() ? error : error.message,
            },
          );
          return;
        },
      ) as FortiOSResponse<FortiOSFirewallAddrGrp6>).results;

    // Find missing addresses and groups
    const missingAddresses = Object.values(fortiOSIPv6Addresses).filter(
      (address) =>
        !fgIPv6Addresses.some(
          (fgAddress) => fgAddress.name === address.name,
        ),
    );

    const missingGroups = Object.values(fortiOSIPv6Groups).filter(
      (group) => !fgIPv6Groups.some((fgGroup) => fgGroup.name === group.name),
    );
    // Create missing addresses and groups on Fortigate
    for (const address of missingAddresses) {
      await firewall.address6.addAddress6(address, { vdom: vdom.name }).then(
        () => {
          logger.info(
            `nsx-firewall-ssi: Created IPv6 address '${address.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'.`,
          );
        },
      ).catch((error: Error) => {
        logger.error(
          `nsx-firewall-ssi: Failed to create IPv6 address '${address.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'`,
          {
            component: "fortios.service",
            method: "deployIPv6",
            error: isDevMode() ? error : error?.message,
          },
        );
      });
    }

    for (const group of missingGroups) {
      await firewall.addrgrp6.addAddressGroup6(group, { vdom: vdom.name }).then(
        () => {
          logger.info(
            `nsx-firewall-ssi: Created IPv6 address group '${group.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'.`,
          );
        },
      ).catch((error: Error) => {
        logger.error(
          `nsx-firewall-ssi: Failed to create IPv6 address group '${group.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'`,
          {
            component: "fortios.service",
            method: "deployIPv6",
            error: isDevMode() ? error : error?.message,
          },
        );
      });
    }
    // Update group if the members have changed
    for (const group of Object.values(fortiOSIPv6Groups)) {
      const existingGroup = fgIPv6Groups.find(
        (fgGroup) => fgGroup.name === group.name,
      );

      if (existingGroup) {
        //Find members only present in NSX
        const added = group.member?.filter(
          (m) => !existingGroup.member?.some((em) => em.name === m.name),
        ) || [];

        //Find members only present in FortiGate
        const removed = existingGroup.member?.filter((m) =>
          !group.member.some((gm) =>
            gm.name === m.name
          )
        ) || [];

        const hasChanged = added.length > 0 || removed.length > 0;

        if (hasChanged) {
          const meta = {
            name: group.name,
            type: "UPDATE",
            src: {
              system: "nsx",
              servers: integrator.managers?.map((m) => m.name),
            },
            dst: {
              system: "fortigate",
              server: firewall.getHostname(),
              options: { vdom: vdom.name },
            },
            changes: {
              added: added.map((a) => a.name),
              removed: removed.map((r) => r.name),
            },
          };
          await firewall.addrgrp6.updateAddressGroup6(group.name, group, {
            vdom: vdom.name,
          }).then(
            () => {
              logger.info(
                `nsx-firewall-ssi: Updated IPv6 address group '${group.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'.`,
                meta,
              );
            },
          ).catch((error: Error) => {
            logger.error(
              `nsx-firewall-ssi: Failed to update IPv6 address group '${group.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'`,
              {
                component: "fortios.service",
                method: "deployIPv6",
                error: isDevMode() ? error : error?.message,
              },
            );
          });

          if (removed.length > 0) {
            for (const address of removed) {
              const inUse = await address6InUse(
                firewall,
                vdom,
                address,
              );

              if (inUse) {
                logger.info(
                  `nsx-firewall-ssi: IPv6 address '${address.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}' is still in use. Skipping deletion.`,
                );
              } else {
                await firewall.address6.deleteAddress6(address.name, {
                  vdom: vdom.name,
                }).then(
                  () => {
                    logger.info(
                      `nsx-firewall-ssi: Deleted IPv6 address '${address.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'.`,
                    );
                  },
                ).catch((error: Error) => {
                  logger.error(
                    `nsx-firewall-ssi: Failed to delete IPv6 address '${address.name}' from integrator '${integrator.name}' on '${firewall.getHostname()}' vdom '${vdom.name}'`,
                    {
                      component: "fortios.service",
                      method: "deployIPv6",
                      error: isDevMode() ? error : error?.message,
                    },
                  );
                });
              }
            }
          }
        }
      }
    }
  } catch (error) {
    throw error;
  }
};
