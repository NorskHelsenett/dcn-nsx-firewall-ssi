/**
 * Logger Configuration - Winston-based logging system for NSX-Firewall-SSI
 * Provides console, file rotation, and Splunk HEC logging with multiple log levels
 * File loggers are only enabled in development mode to avoid container filesystem issues
 */

import winston from "winston";
import DailyRotateFile from "winston-daily-rotate-file";
import {
  EnvLoader,
  isDevMode,
  WinstonHecLogger,
  WinstonLoggerConsoleColors,
  WinstonLoggerLevels,
} from "@norskhelsenett/zeniki";
import https from "node:https";

let hecLogger: WinstonHecLogger | undefined;
let combinedFileLogger: DailyRotateFile | undefined;
let warningFileLogger: DailyRotateFile | undefined;
let errorFileLogger: DailyRotateFile | undefined;
let debugFileLogger: DailyRotateFile | undefined;
let splunkFileLogger: DailyRotateFile | undefined;

const SECRETS_PATH = Deno.env.get("SECRETS_PATH") ?? undefined;
const CONFIG_PATH = Deno.env.get("CONFIG_PATH") ?? undefined;

const envLoader = new EnvLoader(SECRETS_PATH, CONFIG_PATH);

const REQUEST_TIMEOUT = Deno.env.get("REQUEST_TIMEOUT")
  ? parseInt(Deno.env.get("REQUEST_TIMEOUT") as string)
  : 10000;

const _HTTPS_AGENT = new https.Agent({
  rejectUnauthorized: Deno.env.get("DENO_ENV")! != "development", // Set to false to disable certificate verification
  keepAlive: true,
  timeout: REQUEST_TIMEOUT,
});

const SPLUNK_URL = Deno.env.get("SPLUNK_URL") ?? undefined;
const SPLUNK_TOKEN = Deno.env.get("SPLUNK_TOKEN") ?? undefined;

const FILELOG_DIR = Deno.env.get("FILELOG_DIR")
  ? Deno.env.get("FILELOG_DIR")
  : "logs";

const FILELOG_SIZE = Deno.env.get("FILELOG_SIZE")
  ? Deno.env.get("FILELOG_SIZE")
  : "50m"; // 50 megabytes

const FILELOG_DAYS = Deno.env.get("FILELOG_DAYS")
  ? Deno.env.get("FILELOG_DAYS")
  : "30d"; // 30 days

const SPLUNK_INDEX = Deno.env.get("SPLUNK_INDEX") ?? undefined;
const SPLUNK_SOURCE = Deno.env.get("SPLUNK_SOURCE") ?? "ssi";
const SPLUNK_SOURCE_TYPE = Deno.env.get("SPLUNK_SOURCE_TYPE") ??
  "nsx-firewall-ssi:high";
envLoader.close();
/**
 * Determines log level based on environment mode
 * Returns 'debug' in development, 'info' in production
 */
const logLevel = () => {
  return isDevMode() ? "debug" : "info";
};

winston.addColors(WinstonLoggerConsoleColors);

/**
 * Standard log format for console and file output
 */
const format = winston.format.combine(
  winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss.SSS" }),
  winston.format.printf(({ level, message, timestamp }) => {
    return `${timestamp} ${level}: ${message}`;
  }),
);

/**
 * Splunk HEC (HTTP Event Collector) format
 * Structures logs for Splunk ingestion with metadata and event fields
 */
const splunkHECFormat = winston.format.combine(
  winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss.SSS" }),
  winston.format.printf(({ level, message, ...metadata }) => {
    const hecWriterObject = {
      event: {
        level: level,
        message: message,
        // Include any other metadata or custom fields you want
        // The '...meta' captures any additional properties passed to the log function
        meta: metadata && Object.keys(metadata).length > 0
          ? metadata
          : undefined,
      },
      host: Deno.hostname(),
      index: SPLUNK_INDEX,
      source: SPLUNK_SOURCE,
      sourcetype: SPLUNK_SOURCE_TYPE,
      time: Date.now(),
    };

    return JSON.stringify(hecWriterObject);
  }),
);

/**
 * Removes all log levels except for debug (http access) from logs.
 */
const debugFilter = winston.format((info, _opts) => {
  return info.level === "debug" ? info : false;
});

/**
 * Removes log level notice (http access) from logs.
 */
const _noHttpFilter = winston.format((info, _opts) => {
  return info.level === "info" ||
      info.level === "warning" ||
      info.level === "error" ||
      info.level === "debug"
    ? info
    : false;
});

/**
 * Transport configurations for Winston logger
 * Base transport includes only console output
 * File transports are added dynamically in development mode via addFileLogger()
 */
const transports = [
  // Allow the use the console to print the messages

  new winston.transports.Console({
    level: logLevel(),
    handleExceptions: true,
    format: winston.format.combine(
      winston.format.errors({ stack: true }),
      winston.format.colorize({ all: true }),
    ),
  }),
];

/**
 * Main Winston logger instance
 * Configured with custom log levels, formats, and transports
 */
const logger = winston.createLogger({
  level: logLevel(),
  levels: WinstonLoggerLevels,
  format: winston.format.combine(format),
  transports: transports,
});

logger.on("error", (error: Error) => {
  logger.warning(`nsx-firewall-ssi: Error in logger ${error.message}`, {
    component: "logger",
    method: "winston.createLogger",
    error: isDevMode() ? error : (error as Error).message,
  });
});

/**
 * Adds Splunk HEC logger transport if credentials are configured
 * Enables real-time log forwarding to Splunk for monitoring
 */
const addHecLogger = () => {
  try {
    if (SPLUNK_URL && SPLUNK_TOKEN && !hecLogger) {
      hecLogger = new WinstonHecLogger(
        {
          baseURL: SPLUNK_URL,
          headers: {
            "User-Agent": "Winston-HEC-Logger/0.0.1",
            "Content-Type": "application/json",
            Authorization: `Splunk ${SPLUNK_TOKEN}`,
          },
        },
        {
          level: "info",
          format: splunkHECFormat,
        },
      );
      logger.add(hecLogger);
    }
  } catch (error) {
    console.log("Catching error");
    logger.error(
      `nsx-firewall-ssi: Error on WinstonHecLogger,  ${
        (error as Error).message
      }`,
      {
        component: "logger",
        method: "addHecLogger",
        error: isDevMode() ? error : (error as Error).message,
      },
    );
    throw error;
  }
};

/**
 * Removes Splunk HEC logger transport
 * Cleans up the HEC logger instance and removes it from Winston transports
 */
export const removeHecLogger = () => {
  try {
    if (hecLogger) {
      logger.remove(hecLogger);
      hecLogger.dispose();
      hecLogger = undefined;
    }
  } catch (error) {
    logger.error(
      `nsx-firewall-ssi: Error on removeHecLogger,  ${
        (error as Error).message
      }`,
      {
        component: "logger",
        method: "removeHecLogger",
        error: isDevMode() ? error : (error as Error).message,
      },
    );
  }
};

/**
 * Adds file-based logger transports for development mode
 * Creates daily rotating log files for combined, warning, error, and debug logs
 * Only active when DENO_ENV=development to avoid container filesystem issues
 *
 * Log files created:
 * - combined.log: All log levels
 * - warn.log: Warning level and above
 * - error.log: Error level only
 * - debug.log: Debug level only
 */
export const addFileLoggers = () => {
  try {
    if (
      isDevMode() &&
      !combinedFileLogger &&
      !warningFileLogger &&
      !errorFileLogger &&
      !debugFileLogger
    ) {
      // Combined log, combines all logs into one file.
      combinedFileLogger = new DailyRotateFile({
        filename: "combined-%DATE%.log",
        dirname: FILELOG_DIR,
        datePattern: "YYYYMMDD",
        createSymlink: true,
        symlinkName: "combined.log",
        zippedArchive: true,
        maxSize: FILELOG_SIZE,
        maxFiles: FILELOG_DAYS,
        format: winston.format.combine(
          winston.format.errors({ stack: true }),
          winston.format.json(),
        ),
      });

      // Warning log..
      warningFileLogger = new DailyRotateFile({
        level: "warning",
        filename: "warn-%DATE%.log",
        dirname: FILELOG_DIR,
        datePattern: "YYYYMMDD",
        createSymlink: true,
        symlinkName: "warn.log",
        zippedArchive: true,
        maxSize: FILELOG_SIZE,
        maxFiles: FILELOG_DAYS,
        handleExceptions: true,
        format: winston.format.combine(
          winston.format.errors({ stack: true }),
          winston.format.json(),
        ),
      });

      // Error log..
      errorFileLogger = new DailyRotateFile({
        level: "error",
        filename: "error-%DATE%.log",
        dirname: FILELOG_DIR,
        datePattern: "YYYYMMDD",
        createSymlink: true,
        symlinkName: "error.log",
        zippedArchive: true,
        maxSize: FILELOG_SIZE,
        maxFiles: FILELOG_DAYS,
        handleExceptions: true,
        format: winston.format.combine(
          winston.format.errors({ stack: true }),
          winston.format.json(),
        ),
      });

      // Debug log..
      debugFileLogger = new DailyRotateFile({
        level: "debug",
        filename: "debug-%DATE%.log",
        dirname: FILELOG_DIR,
        datePattern: "YYYYMMDD",
        createSymlink: true,
        symlinkName: "debug.log",
        zippedArchive: true,
        maxSize: FILELOG_SIZE,
        maxFiles: FILELOG_DAYS,
        handleExceptions: true,
        format: winston.format.combine(
          debugFilter(),
          winston.format.errors({ stack: true }),
          winston.format.json(),
        ),
      });

      logger.add(combinedFileLogger);
      logger.add(warningFileLogger);
      logger.add(errorFileLogger);
      logger.add(debugFileLogger);
    }
  } catch (error) {
    logger.error(
      `nsx-firewall-ssi: Error on FileLogger,  ${(error as Error).message}`,
      {
        component: "logger",
        method: "addFileLogger",
        error: isDevMode() ? error : (error as Error).message,
      },
    );
  }
};

/**
 * Removes all file-based logger transports
 * Cleans up combined, warning, error, and debug file loggers
 * Useful for switching from file logging to container-based logging
 */
export const removeFileLoggers = () => {
  try {
    if (combinedFileLogger) {
      logger.remove(combinedFileLogger);
      combinedFileLogger = undefined;
    }
    if (warningFileLogger) {
      logger.remove(warningFileLogger);
      warningFileLogger = undefined;
    }
    if (errorFileLogger) {
      logger.remove(errorFileLogger);
      errorFileLogger = undefined;
    }
    if (debugFileLogger) {
      logger.remove(debugFileLogger);
      debugFileLogger = undefined;
    }
  } catch (error) {
    logger.error(
      `nsx-firewall-ssi: Error on removeFileLogger,  ${
        (error as Error).message
      }`,
      {
        component: "logger",
        method: "removeFileLogger",
        error: isDevMode() ? error : (error as Error).message,
      },
    );
  }
};

/**
 * Adds Splunk-formatted file logger for development mode
 * Creates a daily rotating log file with Splunk HEC JSON format
 * Only active when DENO_ENV=development
 * Useful for testing Splunk ingestion locally before deploying
 */
export const addSplunkFileLogger = () => {
  try {
    if (isDevMode() && !splunkFileLogger) {
      splunkFileLogger = new DailyRotateFile({
        level: "info",
        filename: "splunk-%DATE%.log",
        dirname: FILELOG_DIR,
        datePattern: "YYYYMMDD",
        createSymlink: true,
        symlinkName: "splunk.log",
        zippedArchive: true,
        maxSize: FILELOG_SIZE,
        maxFiles: FILELOG_DAYS,
        handleExceptions: true,
        format: winston.format.combine(splunkHECFormat),
      });

      logger.add(splunkFileLogger);
    }
  } catch (error) {
    logger.error(
      `nsx-firewall-ssi: Error on SplunkFileLogger,  ${
        (error as Error).message
      }`,
      {
        component: "logger",
        method: "addSplunkFileLogger",
        error: isDevMode() ? error : (error as Error).message,
      },
    );
  }
};

/**
 * Removes Splunk-formatted file logger transport
 * Cleans up the Splunk file logger instance
 */
export const removeSplunkFileLogger = () => {
  try {
    if (splunkFileLogger) {
      logger.remove(splunkFileLogger);
      splunkFileLogger = undefined;
    }
  } catch (error) {
    logger.error(
      `nsx-firewall-ssi: Error on removeSplunkFileLogger,  ${
        (error as Error).message
      }`,
      {
        component: "logger",
        method: "removeSplunkFileLogger",
        error: isDevMode() ? error : (error as Error).message,
      },
    );
  }
};

// Initialize default loggers
// - HEC logger: Added if SPLUNK_URL and SPLUNK_TOKEN are configured
// - File loggers: Added only in development mode to avoid container filesystem issues
addHecLogger();
addFileLoggers();

logger.debug(`nsx-firewall-ssi: Logger initialized at ${logLevel()} level`);

export default logger;
