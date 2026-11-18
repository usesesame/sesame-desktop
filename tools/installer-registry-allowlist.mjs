export const ALLOWED_REGISTRY_OPERATIONS = [
  /^ReadRegStr \$R[04] HKLM "\$\{SESAME_ENVIRONMENT_KEY\}" "Path"$/,
  /^(?:WriteRegStr|WriteRegExpandStr) HKLM "\$\{SESAME_ENVIRONMENT_KEY\}" "Path" "\$\{VALUE\}"$/,
  /^System::Call 'advapi32::RegGetValueW\(p 0x80000002, w "\$\{SESAME_ENVIRONMENT_KEY\}", w "Path", i 0x1000ffff, \*i \.R4, p 0, p 0\) i \.R5'$/,
  /^ReadRegStr \$SesameOwnsTerminalPath SHCTX "\$\{MANUPRODUCTKEY\}" "\$\{SESAME_PATH_OWNER_VALUE\}"$/,
  /^WriteRegStr SHCTX "\$\{MANUPRODUCTKEY\}" "\$\{SESAME_PATH_OWNER_VALUE\}" "\$\{SESAME_TERMINAL_FOLDER\}"$/,
]

export function unexpectedRegistryOperations(hook) {
  return hook
    .split('\n')
    .map((line) => line.replace(/^\s*;.*$/, '').trim())
    .filter((line) => /^(?:ReadReg|WriteReg|DeleteReg|EnumReg)\w*\s|^System::Call\b|\b(?:HKLM|HKEY_LOCAL_MACHINE|HKCR|HKEY_CLASSES_ROOT|HKU|HKEY_USERS|HKCC|HKEY_CURRENT_CONFIG)\b|0x8000000\d/i.test(line))
    .map((line) => line.replace(/\bHKEY_LOCAL_MACHINE\b/gi, 'HKLM'))
    .filter((line) => !ALLOWED_REGISTRY_OPERATIONS.some((allowed) => allowed.test(line)))
}
