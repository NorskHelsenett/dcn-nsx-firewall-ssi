/**
 * SSI Worker - Main orchestration class for NSX-Firewall synchronization
 * Manages sync operations between NSX and firewall systems (FortiOS, VMware NSX)
 */

import {
  FortiOSDriver,
  isDevMode,
  NAMAPIEndpoint,
  NAMNsxIntegrator,
  NAMv2Driver,
  VMwareNSXDriver,
} from "@norskhelsenett/zeniki";
import {
  FortiOSAddresses,
  FortiOSAddresses6,
  FortiOSAddressGrps,
  FortiOSAddressGrps6,
  mergeAddressObjects,
  mergeGroupObjects,
} from "./ssi.utils.ts";
import https from "node:https";
import packageInfo from "../deno.json" with { type: "json" };
import logger from "./loggers/logger.ts";
import {
  getGroupTagsGroupsAndMembers,
  getVMTagsGroupsAndMembers,
} from "./services/nsx.service.ts";
import { deployIPv4 } from "./services/fortios.service.ts";
import { deployIPv6 } from "./services/fortios.service.ts";

const SSI_NAME = Deno.env.get("SSI_NAME") ?? "SSI_NAME_MISSING";
const USER_AGENT = `${SSI_NAME}/${packageInfo.version}`;
Deno.env.set("USER_AGENT", USER_AGENT);
const REQUEST_TIMEOUT = Deno.env.get("REQUEST_TIMEOUT")
  ? parseInt(Deno.env.get("REQUEST_TIMEOUT") as string)
  : 10000;

const _HTTPS_AGENT = new https.Agent({
  rejectUnauthorized: Deno.env.get("DENO_ENV")! != "development", // Set to false to disable certificate verification
  keepAlive: true,
  timeout: REQUEST_TIMEOUT,
});

const NAM_URL = Deno.env.get("NAM_URL");
const NAM_TOKEN = Deno.env.get("NAM_TOKEN");
const NAM_TEST_INT = Deno.env.get("NAM_TEST_INT");

/**
 * Main worker class that orchestrates NSX to firewall synchronization
 * Initializes API drivers and coordinates deployment to FortiGate and NSX systems
 */
export class SSIWorker {
  private _running: boolean = false;
  private static _nms: NAMv2Driver;
  private _firewall: FortiOSDriver | null = null;
  private _nsx: VMwareNSXDriver | null = null;
  private _run_counter = 0;

  /**
   * Initializes the worker and sets up the NAM API driver
   */
  constructor() {
    if (!SSIWorker._nms && NAM_URL) {
      SSIWorker._nms = new NAMv2Driver({
        baseURL: NAM_URL,
        headers: {
          "User-Agent": USER_AGENT,
          "Content-Type": "application/json",
          Authorization: `Bearer ${NAM_TOKEN}`,
        },
        // TODO: Figure out proper timeout, signal: AbortSignal.timeout(REQUEST_TIMEOUT),
      });
    }
  }

  get isRunning(): boolean {
    return this._running;
  }

  /**
   * Main work method that performs synchronization tasks
   * Fetches integrators, retrieves prefixes from Netbox, and deploys to firewall systems
   * @param priority - Sync priority filter: low, medium, or high
   */
  public async work(priority: string = "low") {
    try {
      if (!this.isRunning) {
        this._running = true;
        logger.debug("nsx-firewall-ssi: Worker running task...");

        const integrators = isDevMode() && NAM_TEST_INT
          ? [
            await SSIWorker._nms.nsx_integrators.getNsxIntegrator(
              NAM_TEST_INT,
              {
                expand: 1,
              },
            ),
          ]
          : ((
            await SSIWorker._nms.nsx_integrators.getNsxIntegrators({
              expand: 1,
              sync_priority: priority,
            })
          )?.results as NAMNsxIntegrator[]);

        // ! Here we go!
        for (const integrator of integrators) {
          logger.info(
            `nsx-firewall-ssi: Processing integrator ${integrator.name}...`,
          );
          const managers = integrator.managers as NAMAPIEndpoint[];
          let fortiOSIPv4Groups: FortiOSAddressGrps = {};
          let fortiOSIPv4Addresses: FortiOSAddresses = {};
          let fortiOSIPv6Groups: FortiOSAddressGrps6 = {};
          let fortiOSIPv6Addresses: FortiOSAddresses6 = {};
          for (const manager of managers) {
            this._nsx = this._configureNSX(manager as NAMAPIEndpoint);
            const lm = manager.type === "local" ||
              manager.type === "global_managed";

            // Fetch VM tags from local manager only
            if (lm) {
              logger.info(
                `nsx-firewall-ssi: Local Manager ${manager.name}...`,
              );

              const result = await getVMTagsGroupsAndMembers(
                this._nsx,
                integrator,
                manager,
              );

              Object.assign(
                fortiOSIPv4Groups,
                result.fortiOSIPv4Groups,
              );
              Object.assign(
                fortiOSIPv4Addresses,
                result.fortiOSIPv4Addresses,
              );
              Object.assign(
                fortiOSIPv6Groups,
                result.fortiOSIPv6Groups,
              );
              Object.assign(
                fortiOSIPv6Addresses,
                result.fortiOSIPv6Addresses,
              );

              logger.info(
                `nsx-firewall-ssi: Local Manager ${manager.name} - Finished with VMs...`,
              );
            }

            // Fetch Group tags from all managers
            const result = await getGroupTagsGroupsAndMembers(
              this._nsx,
              integrator,
              manager,
            );

            // Merge addresses
            fortiOSIPv4Addresses = mergeAddressObjects(
              fortiOSIPv4Addresses,
              result.fortiOSIPv4Addresses,
            );
            fortiOSIPv6Addresses = mergeAddressObjects(
              fortiOSIPv6Addresses,
              result.fortiOSIPv6Addresses,
            );

            // Merge addresses
            fortiOSIPv4Groups = mergeGroupObjects(
              fortiOSIPv4Groups,
              result.fortiOSIPv4Groups,
            );

            fortiOSIPv6Groups = mergeGroupObjects(
              fortiOSIPv6Groups,
              result.fortiOSIPv6Groups,
            );
            logger.info(
              `nsx-firewall-ssi: Manager ${manager.name} - Finished with Groups...`,
            );

            // console.log(fortiOSIPv4Groups);

            for (const fgEndpoint of integrator.fortigate_endpoints) {
              this._firewall = this._configureFirewall(
                fgEndpoint.endpoint as NAMAPIEndpoint,
              );

              await Promise.all(
                fgEndpoint.vdoms.map(async (vdom) => {
                  // await Promise.all([
                  //   deployIPV4(
                  //     integrator,
                  //     this._firewall as FortiOSDriver,
                  //     vdom,
                  //     fortiOSIPv4Groups,
                  //     fortiOSIPv4Addresses,
                  //   ),
                  //   deployIPV6ToVdom(
                  //     this._firewall as FortiOSDriver,
                  //     vdom,
                  //     fortiOSIPv6Groups,
                  //     fortiOSIPv6Addresses,
                  //   ),
                  // ]);
                }),
              );
            }
          }
        }

        // ! Finished

        //  Final cleanup - clear integrators array
        if (isDevMode()) {
          logger.debug(
            `nsx-firewall-ssi: Cleaning up integrators array (${integrators.length} integrators processed)`,
          );
        }
        integrators.length = 0;

        this._running = false;
        this._resetDriverInstances();
        logger.debug("nsx-firewall-ssi: Worker task completed...");
        console.log(
          `nsx-firewall-ssi: Completed run number ${this._run_counter}`,
        );
        return 0;
      } else {
        logger.warning("nsx-firewall-ssi: Worker task already running...");
        return 7;
      }
    } catch (error) {
      this._running = false;
      console.log(
        `nsx-firewall-ssi: Completed run number ${this._run_counter}`,
      );
      console.log(error);
      throw error;
    }
  }

  /**
   * Configures the FortiOS firewall driver with endpoint credentials
   */
  private _configureFirewall(endpoint: NAMAPIEndpoint): FortiOSDriver {
    return new FortiOSDriver({
      baseURL: endpoint.url,
      headers: {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
        Authorization: `Bearer ${endpoint.key}`,
      },
      // TODO: Figure out proper timeout, signal: AbortSignal.timeout(REQUEST_TIMEOUT),,
    });
  }

  /**
   * Configures the VMware NSX driver with endpoint credentials
   */
  private _configureNSX = (endpoint: NAMAPIEndpoint) => {
    const username = endpoint?.user + "";
    const password = endpoint?.pass + "";
    const authString = `${username}:${password}`;
    const encodedAuth = btoa(authString);
    return new VMwareNSXDriver({
      baseURL: endpoint?.url?.replace(
        "/api/v1",
        "",
      ).replace("/global-manager", ""),
      headers: {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
        Authorization: `Basic ${encodedAuth}`,
      },
      // TODO: Figure out proper timeout, signal: AbortSignal.timeout(REQUEST_TIMEOUT),
    });
  };

  private _resetDriverInstances() {
    try {
      logger.debug(`nsx-firewall-ssi: Dereferencing old driver instances.`);
      if (this._firewall) {
        this._firewall.dispose();
        this._firewall = null;
      }
      if (this._nsx) {
        this._nsx.dispose();
        this._nsx = null;
      }
    } catch (error: unknown) {
      logger.warning(
        `nsx-firewall-ssi: Error could not reset one or more driver instances, ${
          (error as Error).message
        }`,
      );
    }
  }
}
