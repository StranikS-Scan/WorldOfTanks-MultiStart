# WorldOfTanks-MultiStart

Patcher for the **x32** and **x64** executable files to unlock multi-launch in the game client for **Lesta** and **Wargaming**. The program uses the well-known list of signatures and downloading it from repo. You can download list manually and put it in the program folder, in this case program will not download list from the network.

The program initially tries to determine the version of the game client from the **"version.xml"** file. Then it analyzes the version of the **"winXX\XXX.exe"** file. If the file **"version.xml"** is not available then the game client version is taken from the **exe**-file properties only. After that, the program tries to find the exact entry in the list of signatures. If she is not there, program finds the nearest known record and offers to use it. So, if the signature does not change when new versions of the game are released, then you do not need to make a new entry in the list of signatures.

![ScreenShot](./Example.png)

## Using (for players)

1. Download the [archive](./zip/) and unzip the **exe**-file to the game **root**-folder or **winXX**-folder
2. Run the **exe**-file to patch the game executable

If you want to patch the **x32** game exe-file, then use the **WOT32** program file, otherwise use **WOT64** program file. When patching an executable file, the program first creates a backup in the form of a **"*.backup"** file. If you want to roll back the changes made by the program, delete the patched file and change the extansion of the backup file to the original one.

## Command line arguments (for mods developers)

The program supports launching from the command line. The list of arguments passing is given below:

WIN32-format  | Required | Description
--------------|----------|------------------------
--wot-path="" |    x     | Path to the game **root**-folder or **winXX**-folder
--silent-mode |          | Do not ask questions
--no-backup   |          | Do not create backup
--no-add-mark |          | Do not add a mark about modification at the end of the exe-file

## Exitcode list

Name                      | Code  | Description
--------------------------|-------|------------------------
ERROR_SUCCESS             | 0     | The operation completed successfully
ERROR_XBIT                | 16001 | The  program xBit does not match the xBit of the WOT exe-file
ERROR_ALREADY_PATCHED     | 16002 | WOT exe-file already patched has a label
ERROR_WOTEXE_INVALID      | 16003 | Could not read WOT exe-file, possibly no access or file is damaged
ERROR_WOTEXE_NOTFOUND     | 16004 | WOT exe-file not found
ERROR_WOTVERSION_NOTFOUND | 16005 | Program could not get information about WOT exe-file version
ERROR_REPO_NOTFOUND       | 16006 | No access to repository with signatures or signs-file not found in repo
ERROR_SIGN_NOTFOUND       | 16007 | No signature found suitable for WOT exe-file

## Add signature to list

Signatures are recorded in the [signatures32.list](./signatures32.list) and [signatures64.list](./signatures64.list) files. One line corresponds to one record. Lines are written in the order of increasing the version number of the game client and the **exe**-file version number of the game. The following is the decryption of the fields:

Field         | Format      | Description
--------------|-------------|-----------------------------------------------------------
Game          | ALL/LMT/WOT | Indication of the game's affiliation: **LMT**-for Lesta game, **WOT**-for Wargaming game, **ALL**-for both games at once
ClientVersion | N.N.N...    | Game client version number from the **"version.xml"** file
FileVersion   | N.N.N...    | Value of the **"FileVersion"** field from the properties of the game **exe**-file. If the value is not known, put a hyphen
FileID        |   N         | ID number of the **exe**-file, located after the **#** symbol in the **"FileVersion"** field. If the value is not known, put a hyphen
OldSign       | [Hexs]      | Signature to find
NewSign       | [Hexs]      | Signature to replace
EntryNumber   |   N         | Match number at which to replace, for example: 1 - replace once only at the first match, 2 - replace once and only at the second match. If the field is hyphen, then all found matches will be replaced

**OldSign** and **newSign** fields contain the signatures themselves. The signature is specified as a sequence of bytes, which should be separated by a space or tab. if any bytes should be ignored then they can be replaced as **XX**.

## Signature search

Keywords to search for new signatures using the [IDA-Disassembler](https://www.hex-rays.com/) are noted in the listing below on the example of **WorldOfTanks.exe 1.5.1.321 #1156535**:
```
.text:0063153F 76 71                             jbe     short loc_6315B2
.text:00631541 6A 40                             push    40h             ; uType
.text:00631543 68 DC F6 B0 01                    push    offset Caption  ; lpCaption
.text:00631548 68 60 F7 B0 01                    push    offset Text     ; lpText
.text:0063154D 6A 00                             push    0               ; hWnd
========================================= KEYWORDS #1 =========================================
.text:0063154F FF 15 24 1B AF 01                 call    ds:MessageBoxW
-----------------------------------------------------------------------------------------------
.text:00631555 8B 55 E8                          mov     edx, [ebp+var_18]
.text:00631558 C6 45 FC 02                       mov     byte ptr [ebp+var_4], 2
.text:0063155C 83 FA 08                          cmp     edx, 8
.text:0063155F 72 34                             jb      short loc_631595
.text:00631561 8B 4D D4                          mov     ecx, dword ptr [ebp+WideCharStr]
.text:00631564 8D 14 55 02 00 00+                lea     edx, ds:2[edx*2]
.text:0063156B 8B C1                             mov     eax, ecx
.text:0063156D 81 FA 00 10 00 00                 cmp     edx, 1000h
.text:00631573 72 16                             jb      short loc_63158B
.text:00631575 8B 49 FC                          mov     ecx, [ecx-4]
.text:00631578 83 C2 23                          add     edx, 23h
.text:0063157B 2B C1                             sub     eax, ecx
.text:0063157D 83 C0 FC                          add     eax, 0FFFFFFFCh
.text:00631580 83 F8 1F                          cmp     eax, 1Fh
.text:00631583 76 06                             jbe     short loc_63158B
========================================= KEYWORDS #2 =========================================
.text:00631585 FF 15 3C 1F AF 01                 call    ds:_invalid_parameter_noinfo_noreturn
-----------------------------------------------------------------------------------------------
.text:0063158B                   loc_63158B:                             ; CODE XREF: sub_6312C0+2B3^j
.text:0063158B                                                           ; sub_6312C0+2C3^j
.text:0063158B 52                                push    edx
.text:0063158C 51                                push    ecx             ; Memory
.text:0063158D E8 9F F4 32 01                    call    sub_1960A31
.text:00631592 83 C4 08                          add     esp, 8
.text:00631595                   loc_631595:                             ; CODE XREF: sub_6312C0+29F^j
.text:00631595 33 C0                             xor     eax, eax
.text:00631597 C7 45 E4 00 00 00+                mov     [ebp+var_1C], 0
.text:0063159E C7 45 E8 07 00 00+                mov     [ebp+var_18], 7
.text:006315A5 66 89 45 D4                       mov     [ebp+WideCharStr], ax
.text:006315A9 C6 45 FC 07                       mov     byte ptr [ebp+var_4], 7
.text:006315AD E9 28 17 00 00                    jmp     loc_632CDA
.text:006315B2                   loc_6315B2:                             ; CODE XREF: sub_6312C0+27F^j
.text:006315B2 E8 09 9E 71 00                    call    sub_D4B3C0
.text:006315B7 8B C8                             mov     ecx, eax
.text:006315B9 E8 D2 9C 71 00                    call    sub_D4B290
.text:006315BE E8 FD 9D 71 00                    call    sub_D4B3C0
.text:006315C3 8B C8                             mov     ecx, eax
.text:006315C5 E8 36 A8 71 00                    call    sub_D4BE00
.text:006315CA 83 F8 05                          cmp     eax, 5
.text:006315CD 0F 84 95 16 00 00                 jz      loc_632C68
.text:006315D3 E8 E8 9D 71 00                    call    sub_D4B3C0
.text:006315D8 6A 00                             push    0
.text:006315DA 8B C8                             mov     ecx, eax
.text:006315DC E8 6F 9F 71 00                    call    sub_D4B550
.text:006315E1 84 C0                             test    al, al
========================================= REPLACEABLE CODE =========================================
.text:006315E3 74 75                             jz      short loc_63165A ; [74 75   74<-EB   [EB 75
.text:006315E5 E8 D6 9D 71 00                    call    sub_D4B3C0       ;  E8]               E8]
----------------------------------------------------------------------------------------------------
```
