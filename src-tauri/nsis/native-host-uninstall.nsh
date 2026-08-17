; Remove only the per-user browser native-host registration owned by Sesame.
; All user vault data and all browser data are deliberately outside this hook.
!include LogicLib.nsh
!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode <> 1
    DeleteRegKey HKCU "Software\Google\Chrome\NativeMessagingHosts\app.usesesame.browser"
    DeleteRegKey HKCU "Software\Microsoft\Edge\NativeMessagingHosts\app.usesesame.browser"
    Delete "$LOCALAPPDATA\Sesame\native-messaging\app.usesesame.browser.json"
    RMDir "$LOCALAPPDATA\Sesame\native-messaging"
  ${EndIf}
!macroend
