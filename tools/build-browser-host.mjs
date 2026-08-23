#!/usr/bin/env node
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { buildBrowserHost } from './browser-host.mjs'

const workspace = dirname(dirname(fileURLToPath(import.meta.url)))

buildBrowserHost({ manifest: join(workspace, 'src-tauri', 'Cargo.toml'), release: false })
