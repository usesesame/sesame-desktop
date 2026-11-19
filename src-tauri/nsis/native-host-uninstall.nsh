; Remove only the per-user browser native-host registration owned by Sesame and
; the cli folder entry Sesame added to the system Path.
; All user vault data and all browser data are deliberately outside this hook.
!include LogicLib.nsh

!define SESAME_TERMINAL_FOLDER "$INSTDIR\cli"
!define SESAME_PATH_OWNER_VALUE "TerminalPathAdded"
!define SESAME_PATH_STATUS_VALUE "TerminalPathStatus"

Var SesameOwnsTerminalPath
Var SesameTerminalPathLeft

!macro SESAME_ADD_TERMINAL_PATH
  Push $0
  Push $1
  ClearErrors
  ExecWait '"$INSTDIR\cli\sesame.exe" --add-to-machine-path' $0
  ${If} ${Errors}
    StrCpy $0 "not started"
  ${EndIf}
  ${If} $0 == "0"
    ClearErrors
    WriteRegStr SHCTX "${MANUPRODUCTKEY}" "${SESAME_PATH_OWNER_VALUE}" "${SESAME_TERMINAL_FOLDER}"
    ${If} ${Errors}
      ClearErrors
      ExecWait '"$INSTDIR\cli\sesame.exe" --remove-from-machine-path' $1
      ${If} ${Errors}
        StrCpy $1 "not started"
      ${EndIf}
      ${If} $1 == "0"
        StrCpy $0 "not recorded, taken off again"
        DetailPrint "Sesame could not record that it added ${SESAME_TERMINAL_FOLDER} to the system Path, so it took the entry off again. Add it by hand to use the sesame command."
      ${Else}
        StrCpy $0 "not recorded, left in place"
        DetailPrint "Sesame added ${SESAME_TERMINAL_FOLDER} to the system Path but could not record it, so uninstalling will not remove it. Remove the entry by hand when you uninstall Sesame."
      ${EndIf}
    ${Else}
      DetailPrint "Sesame added ${SESAME_TERMINAL_FOLDER} to the system Path."
    ${EndIf}
  ${ElseIf} $0 == "10"
    DetailPrint "The system Path already holds ${SESAME_TERMINAL_FOLDER}, so Sesame left it as it was."
  ${ElseIf} $0 == "14"
    DetailPrint "The system Path has no room for ${SESAME_TERMINAL_FOLDER}, so Sesame left it as it was. Remove entries you no longer need from the Path first, then add the folder to use the sesame command."
  ${Else}
    DetailPrint "Sesame could not add ${SESAME_TERMINAL_FOLDER} to the system Path. Add it by hand to use the sesame command."
  ${EndIf}
  WriteRegStr SHCTX "${MANUPRODUCTKEY}" "${SESAME_PATH_STATUS_VALUE}" "$0"
  Pop $1
  Pop $0
!macroend

!macro SESAME_REMOVE_TERMINAL_PATH
  ${If} $UpdateMode <> 1
  ${AndIf} $SesameOwnsTerminalPath S== "${SESAME_TERMINAL_FOLDER}"
    Push $0
    sesame_remove_terminal_path:
    StrCpy $SesameTerminalPathLeft 0
    ClearErrors
    ExecWait '"$INSTDIR\cli\sesame.exe" --remove-from-machine-path' $0
    ${If} ${Errors}
      StrCpy $0 "not started"
    ${EndIf}
    ${If} $0 == "0"
      DetailPrint "Sesame removed ${SESAME_TERMINAL_FOLDER} from the system Path."
    ${ElseIf} $0 == "10"
      DetailPrint "The system Path no longer holds ${SESAME_TERMINAL_FOLDER}, so Sesame left it as it was."
    ${ElseIf} $0 == "13"
      DetailPrint "The system Path holds ${SESAME_TERMINAL_FOLDER} in a form Sesame did not add, or more than once, so Sesame left it. Remove the entries you no longer need by hand."
    ${Else}
      DetailPrint "Sesame could not remove ${SESAME_TERMINAL_FOLDER} from the system Path, outcome $0."
      StrCpy $SesameTerminalPathLeft 1
      ${IfNot} ${Silent}
      ${AndIf} $PassiveMode <> 1
        MessageBox MB_ICONEXCLAMATION|MB_ABORTRETRYIGNORE "Sesame could not remove ${SESAME_TERMINAL_FOLDER} from the system Path.$\r$\n$\r$\nChoose Retry to try again, Ignore to finish the uninstall and remove the entry by hand, or Abort to stop and keep Sesame installed." IDRETRY sesame_remove_terminal_path IDIGNORE sesame_remove_terminal_path_done
        Pop $0
        Abort "Sesame could not remove ${SESAME_TERMINAL_FOLDER} from the system Path, so it stopped and kept Sesame installed. Run the uninstaller again to retry."
      ${EndIf}
    ${EndIf}
    sesame_remove_terminal_path_done:
    Pop $0
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro SESAME_ADD_TERMINAL_PATH
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $SesameTerminalPathLeft = 1
    ClearErrors
    WriteRegStr SHCTX "${MANUPRODUCTKEY}" "${SESAME_PATH_OWNER_VALUE}" "${SESAME_TERMINAL_FOLDER}"
    ${If} ${Errors}
      DetailPrint "Sesame could not keep its record of ${SESAME_TERMINAL_FOLDER} on the system Path. Remove the entry by hand."
    ${Else}
      DetailPrint "Sesame kept its record of ${SESAME_TERMINAL_FOLDER} on the system Path, so the next install and uninstall can remove it."
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ReadRegStr $SesameOwnsTerminalPath SHCTX "${MANUPRODUCTKEY}" "${SESAME_PATH_OWNER_VALUE}"
!macroend

!macro SESAME_UNREGISTER_NATIVE_HOST
  ${If} $UpdateMode <> 1
    ExecWait '"$INSTDIR\sesame-browser-host.exe" unregister'
  ${EndIf}
!macroend
