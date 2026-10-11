; Instalador de MailSentry para Windows (Inno Setup 6).
; Construir:  ISCC herramientas\instalador.iss   (antes: python herramientas\construir_exe.py)
; No pide permisos de administrador: se instala solo para el usuario actual.

#define Version "1.0.0"

[Setup]
AppId={{6E1B3C52-4A0D-4C9B-9A57-5D7E4C2B1F10}
AppName=MailSentry
AppVersion={#Version}
AppPublisher=H4nn-sz
DefaultDirName={localappdata}\Programs\MailSentry
DefaultGroupName=MailSentry
PrivilegesRequired=lowest
OutputDir=..\dist
OutputBaseFilename=Instalar-MailSentry-{#Version}
SetupIconFile=mailsentry.ico
UninstallDisplayIcon={app}\MailSentry.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=force
RestartApplications=no

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "escritorio"; Description: "Crear un acceso directo en el escritorio"; Flags: checkedonce
Name: "iniciowindows"; Description: "Abrir MailSentry al iniciar Windows (para que siga vigilando el correo)"; Flags: unchecked

[Files]
Source: "..\dist\MailSentry\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\MailSentry"; Filename: "{app}\MailSentry.exe"
Name: "{userdesktop}\MailSentry"; Filename: "{app}\MailSentry.exe"; Tasks: escritorio
Name: "{userstartup}\MailSentry"; Filename: "{app}\MailSentry.exe"; Tasks: iniciowindows

[Run]
Filename: "{app}\MailSentry.exe"; Description: "Abrir MailSentry ahora"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM MailSentry.exe"; Flags: runhidden; RunOnceId: "CerrarMailSentry"
