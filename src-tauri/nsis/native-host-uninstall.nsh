; Remove only the per-user browser native-host registration owned by Sesame and
; the cli folder entry Sesame added to the system Path.
; All user vault data and all browser data are deliberately outside this hook.
!include LogicLib.nsh
!include WinMessages.nsh

!define SESAME_ENVIRONMENT_KEY "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
!define SESAME_TERMINAL_FOLDER "$INSTDIR\cli"
!define SESAME_PATH_OWNER_VALUE "TerminalPathAdded"

Var SesameOwnsTerminalPath

!macro SESAME_SCAN_PATH PATH KEPT FOUND EXACT
  StrCpy ${KEPT} ""
  StrCpy ${FOUND} 0
  StrCpy ${EXACT} 0
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
        IntOp ${FOUND} ${FOUND} + 1
        ${If} $R5 S== "${SESAME_TERMINAL_FOLDER}"
          IntOp ${EXACT} ${EXACT} + 1
        ${EndIf}
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

!macro SESAME_READ_PATH
  ClearErrors
  ReadRegStr $R0 HKLM "${SESAME_ENVIRONMENT_KEY}" "Path"
  StrCpy $R3 0
  ${If} ${Errors}
    StrCpy $R3 1
  ${EndIf}
  StrLen $R4 $R0
  IntOp $R4 $R4 + 1
  ${If} $R4 >= ${NSIS_MAX_STRLEN}
    StrCpy $R3 1
  ${EndIf}
!macroend

!macro SESAME_WRITE_PATH VALUE FAILED
  StrCpy $R6 0
  StrCpy $R4 0
  StrCpy $R5 -1
  System::Call 'advapi32::RegGetValueW(p 0x80000002, w "${SESAME_ENVIRONMENT_KEY}", w "Path", i 0x1000ffff, *i .R4, p 0, p 0) i .R5'
  StrCpy $R7 $R4
  ClearErrors
  ReadRegStr $R4 HKLM "${SESAME_ENVIRONMENT_KEY}" "Path"
  ${If} ${Errors}
  ${OrIf} $R4 S!= $R0
    DetailPrint "Another program changed the system Path while Sesame was working, so Sesame left it as it was. ${FAILED}"
  ${Else}
    ClearErrors
    ${If} $R5 = 0
    ${AndIf} $R7 = 1
      WriteRegStr HKLM "${SESAME_ENVIRONMENT_KEY}" "Path" "${VALUE}"
    ${ElseIf} $R5 = 0
    ${AndIf} $R7 = 2
      WriteRegExpandStr HKLM "${SESAME_ENVIRONMENT_KEY}" "Path" "${VALUE}"
    ${Else}
      SetErrors
    ${EndIf}
    ${If} ${Errors}
      DetailPrint "${FAILED}"
    ${Else}
      StrCpy $R6 1
      SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000
    ${EndIf}
  ${EndIf}
!macroend

!macro SESAME_ADD_TERMINAL_PATH
  !insertmacro SESAME_SAVE_REGISTERS
  !insertmacro SESAME_READ_PATH
  ${If} $R3 = 1
  ${OrIf} $R0 == ""
    DetailPrint "Sesame left the system Path as it was because it could not read all of it. Add ${SESAME_TERMINAL_FOLDER} to Path to use the sesame command."
  ${Else}
    !insertmacro SESAME_SCAN_PATH $R0 $R1 $R2 $R4
    ${If} $R2 = 0
      StrLen $R3 $R0
      StrLen $R4 "${SESAME_TERMINAL_FOLDER}"
      IntOp $R3 $R3 + $R4
      IntOp $R3 $R3 + 2
      ${If} $R3 >= ${NSIS_MAX_STRLEN}
        DetailPrint "Sesame left the system Path as it was because adding to it would cut it short. Add ${SESAME_TERMINAL_FOLDER} to Path to use the sesame command."
      ${Else}
        StrCpy $R9 $R0 1 -1
        ${If} $R9 == ";"
          StrCpy $R1 "$R0${SESAME_TERMINAL_FOLDER};"
        ${Else}
          StrCpy $R1 "$R0;${SESAME_TERMINAL_FOLDER}"
        ${EndIf}
        !insertmacro SESAME_WRITE_PATH $R1 "Sesame could not add ${SESAME_TERMINAL_FOLDER} to the system Path. Add it by hand to use the sesame command."
        ${If} $R6 = 1
          WriteRegStr SHCTX "${MANUPRODUCTKEY}" "${SESAME_PATH_OWNER_VALUE}" "${SESAME_TERMINAL_FOLDER}"
        ${EndIf}
      ${EndIf}
    ${EndIf}
  ${EndIf}
  !insertmacro SESAME_RESTORE_REGISTERS
!macroend

!macro SESAME_REMOVE_TERMINAL_PATH
  !insertmacro SESAME_SAVE_REGISTERS
  !insertmacro SESAME_READ_PATH
  ${If} $R3 = 1
  ${OrIf} $R0 == ""
    DetailPrint "Sesame left the system Path as it was because it could not read all of it. Remove ${SESAME_TERMINAL_FOLDER} from Path if it is there."
  ${Else}
    !insertmacro SESAME_SCAN_PATH $R0 $R1 $R2 $R4
    ${If} $R2 = 1
    ${AndIf} $R4 = 1
      !insertmacro SESAME_WRITE_PATH $R1 "Sesame could not remove ${SESAME_TERMINAL_FOLDER} from the system Path. Remove it by hand."
    ${ElseIf} $R2 > 0
      DetailPrint "The system Path holds ${SESAME_TERMINAL_FOLDER} in a form Sesame did not add, so Sesame left it. Remove the entries you no longer need by hand."
    ${EndIf}
  ${EndIf}
  !insertmacro SESAME_RESTORE_REGISTERS
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro SESAME_ADD_TERMINAL_PATH
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ReadRegStr $SesameOwnsTerminalPath SHCTX "${MANUPRODUCTKEY}" "${SESAME_PATH_OWNER_VALUE}"
  ${If} $UpdateMode <> 1
    ExecWait '"$INSTDIR\sesame-browser-host.exe" unregister'
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $UpdateMode <> 1
  ${AndIf} $SesameOwnsTerminalPath S== "${SESAME_TERMINAL_FOLDER}"
    !insertmacro SESAME_REMOVE_TERMINAL_PATH
  ${EndIf}
!macroend
