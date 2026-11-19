; Remove only the per-user browser native-host registration owned by Sesame and
; the cli folder entry Sesame added to the system Path.
; All user vault data and all browser data are deliberately outside this hook.
!include LogicLib.nsh

!define SESAME_TERMINAL_FOLDER "$INSTDIR\cli"
!define SESAME_PATH_OWNER_VALUE "TerminalPathAdded"
!define SESAME_PATH_STATUS_VALUE "TerminalPathStatus"

Var SesameOwnsTerminalPath

!macro SESAME_ADD_TERMINAL_PATH
  Push $0
  ClearErrors
  ExecWait '"$INSTDIR\cli\sesame.exe" --add-to-machine-path' $0
  ${If} ${Errors}
    StrCpy $0 "not started"
  ${EndIf}
  ${If} $0 == "0"
    WriteRegStr SHCTX "${MANUPRODUCTKEY}" "${SESAME_PATH_OWNER_VALUE}" "${SESAME_TERMINAL_FOLDER}"
    DetailPrint "Sesame added ${SESAME_TERMINAL_FOLDER} to the system Path."
  ${ElseIf} $0 == "10"
    DetailPrint "The system Path already holds ${SESAME_TERMINAL_FOLDER}, so Sesame left it as it was."
  ${Else}
    DetailPrint "Sesame could not add ${SESAME_TERMINAL_FOLDER} to the system Path. Add it by hand to use the sesame command."
  ${EndIf}
  WriteRegStr SHCTX "${MANUPRODUCTKEY}" "${SESAME_PATH_STATUS_VALUE}" "$0"
  Pop $0
!macroend

!macro SESAME_REMOVE_TERMINAL_PATH
  ${If} $UpdateMode <> 1
  ${AndIf} $SesameOwnsTerminalPath S== "${SESAME_TERMINAL_FOLDER}"
    Push $0
    ClearErrors
    ExecWait '"$INSTDIR\cli\sesame.exe" --remove-from-machine-path' $0
    ${If} ${Errors}
      StrCpy $0 "not started"
    ${EndIf}
    ${If} $0 == "0"
      DetailPrint "Sesame removed ${SESAME_TERMINAL_FOLDER} from the system Path."
    ${ElseIf} $0 == "10"
      DetailPrint "The system Path holds ${SESAME_TERMINAL_FOLDER} in a form Sesame did not add, or more than once, so Sesame left it. Remove the entries you no longer need by hand."
    ${Else}
      DetailPrint "Sesame could not remove ${SESAME_TERMINAL_FOLDER} from the system Path. Remove it by hand."
    ${EndIf}
    Pop $0
  ${EndIf}
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
