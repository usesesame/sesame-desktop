; Remove only the per-user browser native-host registration owned by Sesame and
; the cli folder entry Sesame adds to the system Path.
; All user vault data and all browser data are deliberately outside this hook.
!include LogicLib.nsh
!include WinMessages.nsh

!define SESAME_ENVIRONMENT_KEY "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
!define SESAME_TERMINAL_FOLDER "$INSTDIR\cli"

!macro SESAME_SCAN_PATH PATH KEPT FOUND
  StrCpy ${KEPT} ""
  StrCpy ${FOUND} 0
  StrCpy $R5 ""
  StrCpy $R6 0
  StrCpy $R8 0
  StrLen $R7 ${PATH}
  ${Do}
    ${If} $R6 < $R7
      StrCpy $R9 ${PATH} 1 $R6
    ${Else}
      StrCpy $R9 ";"
    ${EndIf}
    ${If} $R9 == ";"
      ${If} $R5 == "${SESAME_TERMINAL_FOLDER}"
      ${OrIf} $R5 == "${SESAME_TERMINAL_FOLDER}\"
        StrCpy ${FOUND} 1
      ${Else}
        ${If} $R8 > 0
          StrCpy ${KEPT} "${KEPT};"
        ${EndIf}
        StrCpy ${KEPT} "${KEPT}$R5"
        IntOp $R8 $R8 + 1
      ${EndIf}
      StrCpy $R5 ""
    ${Else}
      StrCpy $R5 "$R5$R9"
    ${EndIf}
    IntOp $R6 $R6 + 1
  ${LoopUntil} $R6 > $R7
!macroend

!macro SESAME_SAVE_REGISTERS
  Push $R0
  Push $R1
  Push $R2
  Push $R3
  Push $R4
  Push $R5
  Push $R6
  Push $R7
  Push $R8
  Push $R9
!macroend

!macro SESAME_RESTORE_REGISTERS
  Pop $R9
  Pop $R8
  Pop $R7
  Pop $R6
  Pop $R5
  Pop $R4
  Pop $R3
  Pop $R2
  Pop $R1
  Pop $R0
!macroend

!macro SESAME_ADD_TERMINAL_PATH
  !insertmacro SESAME_SAVE_REGISTERS
  ClearErrors
  ReadRegStr $R0 HKLM "${SESAME_ENVIRONMENT_KEY}" "Path"
  ${If} ${Errors}
  ${OrIf} $R0 == ""
    DetailPrint "Sesame left the system Path as it was because it could not read all of it. Add ${SESAME_TERMINAL_FOLDER} to Path to use the sesame command."
  ${Else}
    !insertmacro SESAME_SCAN_PATH $R0 $R1 $R2
    ${If} $R2 <> 1
      StrLen $R3 $R0
      StrLen $R4 "${SESAME_TERMINAL_FOLDER}"
      IntOp $R3 $R3 + $R4
      IntOp $R3 $R3 + 2
      ${If} $R3 >= ${NSIS_MAX_STRLEN}
        DetailPrint "Sesame left the system Path as it was because adding to it would cut it short. Add ${SESAME_TERMINAL_FOLDER} to Path to use the sesame command."
      ${Else}
        StrCpy $R9 $R0 1 -1
        ${If} $R9 == ";"
          WriteRegExpandStr HKLM "${SESAME_ENVIRONMENT_KEY}" "Path" "$R0${SESAME_TERMINAL_FOLDER}"
        ${Else}
          WriteRegExpandStr HKLM "${SESAME_ENVIRONMENT_KEY}" "Path" "$R0;${SESAME_TERMINAL_FOLDER}"
        ${EndIf}
        SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000
      ${EndIf}
    ${EndIf}
  ${EndIf}
  !insertmacro SESAME_RESTORE_REGISTERS
!macroend

!macro SESAME_REMOVE_TERMINAL_PATH
  !insertmacro SESAME_SAVE_REGISTERS
  ClearErrors
  ReadRegStr $R0 HKLM "${SESAME_ENVIRONMENT_KEY}" "Path"
  ${If} ${Errors}
  ${OrIf} $R0 == ""
    DetailPrint "Sesame left the system Path as it was because it could not read all of it. Remove ${SESAME_TERMINAL_FOLDER} from Path if it is there."
  ${Else}
    !insertmacro SESAME_SCAN_PATH $R0 $R1 $R2
    ${If} $R2 = 1
      WriteRegExpandStr HKLM "${SESAME_ENVIRONMENT_KEY}" "Path" "$R1"
      SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000
    ${EndIf}
  ${EndIf}
  !insertmacro SESAME_RESTORE_REGISTERS
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro SESAME_ADD_TERMINAL_PATH
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode <> 1
    ExecWait '"$INSTDIR\sesame-browser-host.exe" unregister'
    !insertmacro SESAME_REMOVE_TERMINAL_PATH
  ${EndIf}
!macroend
