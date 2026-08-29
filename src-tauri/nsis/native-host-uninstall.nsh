; Remove only the per-user browser native-host registration owned by Sesame.
; All user vault data and all browser data are deliberately outside this hook.
!include LogicLib.nsh
!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode <> 1
    ExecWait '"$INSTDIR\sesame-browser-host.exe" unregister'
  ${EndIf}
!macroend
