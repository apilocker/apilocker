import { execSync } from 'child_process';
import * as os from 'os';
import * as crypto from 'crypto';

export interface DeviceInfo {
  hostname: string;
  platform: string;
  platform_version: string;
  fingerprint: string;
}

export function collectDeviceInfo(): DeviceInfo {
  const hostname = os.hostname();
  const platform = os.platform();
  const platform_version = os.release();

  // Collect hardware identifiers
  const identifiers: string[] = [hostname, platform, os.arch()];

  try {
    if (platform === 'darwin') {
      // macOS: hardware UUID
      const hwUuid = execSync(
        "ioreg -d2 -c IOPlatformExpertDevice | awk -F'\"' '/IOPlatformUUID/{print $(NF-1)}'",
        { encoding: 'utf-8' }
      ).trim();
      identifiers.push(hwUuid);

      // macOS: serial number
      const serial = execSync(
        "ioreg -l | grep IOPlatformSerialNumber | awk -F'\"' '{print $4}'",
        { encoding: 'utf-8' }
      ).trim();
      identifiers.push(serial);
    } else if (platform === 'linux') {
      // Linux: machine-id
      try {
        const machineId = execSync('cat /etc/machine-id', { encoding: 'utf-8' }).trim();
        identifiers.push(machineId);
      } catch {
        // Fall back to hostname-based identifier
      }
    } else if (platform === 'win32') {
      // Windows: machine GUID
      try {
        const guid = execSync(
          'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
          { encoding: 'utf-8' }
        ).trim();
        identifiers.push(guid);
      } catch {
        // Fall back
      }
    }
  } catch {
    // If hardware collection fails, fall back to hostname + platform
  }

  // Create a composite fingerprint hash
  const fingerprint = crypto
    .createHash('sha256')
    .update(identifiers.join('::'))
    .digest('hex');

  return { hostname, platform, platform_version, fingerprint };
}
