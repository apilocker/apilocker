#!/usr/bin/env node
import { Command } from 'commander';
import { registerCommand } from './commands/register';
import { storeCommand } from './commands/store';
import { listCommand } from './commands/list';
import { deleteCommand } from './commands/delete';
import { tokenCommand } from './commands/token';
import { activityCommand } from './commands/activity';
import { devicesCommand } from './commands/devices';
import { runCommand } from './commands/run';
import { getCommand } from './commands/get';
import { envCommand } from './commands/env';
import { initCommand } from './commands/init';
import { importCommand } from './commands/import';
import { rotateCommand } from './commands/rotate';
import { renameCommand } from './commands/rename';
import { pauseCommand, resumeCommand } from './commands/pause';
import { doctorCommand } from './commands/doctor';
import { updateCommand } from './commands/update';
import { mcpCommand } from './commands/mcp';
import { oauthCommand } from './commands/oauth';
import { maybeShowFirstRunBanner } from './banner';

// First-run welcome banner — prints once, the very first time any command
// is invoked on this machine. Tracked via ~/.apilocker/.welcome-shown.
maybeShowFirstRunBanner();

const program = new Command();

program
  .name('apilocker')
  .description('API Locker — one vault for LLM keys, service API keys, and OAuth credentials')
  .version('1.0.3');

// Auth / device management
program.addCommand(registerCommand);
program.addCommand(devicesCommand);

// Credential management
program.addCommand(storeCommand);
program.addCommand(listCommand);
program.addCommand(deleteCommand);
program.addCommand(rotateCommand);
program.addCommand(renameCommand);   // new in 1.0.0
program.addCommand(pauseCommand);    // new in 1.0.0
program.addCommand(resumeCommand);   // new in 1.0.0
program.addCommand(importCommand);

// Injection primitives — the "replace your .env" trio
program.addCommand(runCommand);
program.addCommand(getCommand);
program.addCommand(envCommand);
program.addCommand(initCommand);

// Scoped tokens for app/proxy use
program.addCommand(tokenCommand);

// Observability
program.addCommand(activityCommand);

// Health + maintenance
program.addCommand(doctorCommand);
program.addCommand(updateCommand);

// MCP integration — stdio bridge + config helper (new in 1.0.0)
program.addCommand(mcpCommand);

// OAuth 2.1 grant management (new in 1.0.3)
program.addCommand(oauthCommand);

program.parse();
