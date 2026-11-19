export const ALLOWED_REGISTRY_OPERATIONS = [
  /^ReadRegStr \$SesameOwnsTerminalPath SHCTX "\$\{MANUPRODUCTKEY\}" "\$\{SESAME_PATH_OWNER_VALUE\}"$/,
  /^WriteRegStr SHCTX "\$\{MANUPRODUCTKEY\}" "\$\{SESAME_PATH_OWNER_VALUE\}" "\$\{SESAME_TERMINAL_FOLDER\}"$/,
  /^WriteRegStr SHCTX "\$\{MANUPRODUCTKEY\}" "\$\{SESAME_PATH_STATUS_VALUE\}" "\$0"$/,
]

export function unexpectedRegistryOperations(hook) {
  return hook
    .split('\n')
    .map((line) => line.replace(/^\s*;.*$/, '').trim())
    .filter((line) => /^(?:ReadReg|WriteReg|DeleteReg|EnumReg)\w*\s|^System::Call\b|\b(?:HKLM|HKEY_LOCAL_MACHINE|HKCR|HKEY_CLASSES_ROOT|HKU|HKEY_USERS|HKCC|HKEY_CURRENT_CONFIG)\b|0x8000000\d/i.test(line))
    .map((line) => line.replace(/\bHKEY_LOCAL_MACHINE\b/gi, 'HKLM'))
    .filter((line) => !ALLOWED_REGISTRY_OPERATIONS.some((allowed) => allowed.test(line)))
}
