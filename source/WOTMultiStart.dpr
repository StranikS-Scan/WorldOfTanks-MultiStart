program WOTMultiStart;

{$APPTYPE CONSOLE}

uses
  Windows, Classes, SysUtils, StrUtils, WinInet;

{$DEFINE WOT32} //Do comment line to compile WOT64-version

{$IFDEF WOT32}
  {$R Manifest32.res}
{$ELSE}
  {$R Manifest64.res}
{$ENDIF}

const
  C_APP_VERSION             = '1.0.6';
  C_APP_DATE                = '08/11/2021';
  C_APP_HEADER              = 'MultiStart for WOT ver.%s %s (C) 2014-2021 StranikS_Scan:';

  C_ARG_WOT_PATH_WIN32      = '--wot-path=';
  C_ARG_SILENT_MODE_WIN32   = '--silent-mode';
  C_ARG_CREATE_BACKUP_WIN32 = '--no-backup';
  C_ARG_ADD_MARK_WIN32      = '--no-add-mark';

  C_WOT32EXE_FOLDER         = 'win32';
  C_WOT64EXE_FOLDER         = 'win64';
  {$IFDEF WOT32}
  C_SIGNATURES_FILENAME     = 'signatures.list';
  {$ELSE}
  C_SIGNATURES_FILENAME     = 'signatures64.list';
  {$ENDIF}
  C_SIGNATURELIST_URL       = 'https://raw.githubusercontent.com/StranikS-Scan/WorldOfTanks-MultiStart/master/'+C_SIGNATURES_FILENAME;

  C_USER_AGENT_DEFAULT      = 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36';
  C_CONTENT_TYPE_DEFAULT    = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3';

  C_ATTEMPTS_TIMEOUT        = 500;

  C_MODIFICATION_MARK       = 'WMSP'; //Wot MultiStart Program
  C_DATETIME_MASK           = 'ddmmyyyyhhnnss';

  ERROR_XBIT                = 16001;
  ERROR_ALREADY_PATCHED     = 16002;
  ERROR_WOTEXE_INVALID      = 16003;
  ERROR_WOTEXE_NOTFOUND     = 16004;
  ERROR_WOTVERSION_NOTFOUND = 16005;
  ERROR_REPO_NOTFOUND       = 16006;
  ERROR_SIGN_NOTFOUND       = 16007;

var
  V_ARG_WOT_PATH: string       = '';
  V_ARG_SILENT_MODE: Boolean   = False;
  V_ARG_CREATE_BACKUP: Boolean = True;
  V_ARG_ADD_MARK: Boolean      = True;

type
  AByte = array of Byte;
  AInteger = array of Integer;

  REntryNumber = record
    All: Boolean;    //Replace all matches
    Number: Integer; //Match number to replace
  end;

  RHex = record
    Any: Boolean; //if XX then True
    Byte: Byte;   //$74
  end;

  AHex = array of RHex;

  RVersion = record
    Numbers: AInteger;   //[1,6,0,1]
    Text: string;        //"1.6.0.1"
    Count, ID: Integer;  //4, #123232
  end;

  RSign = record
    OldSign, NewSign: AHex;
    EntryNumber: REntryNumber;
    XmlVersion, ExeVersion: RVersion;
  end;

  TStatus = (StOK, StNotFound, StNotBackup, StError);

  RReplaceResult = record
    Status: TStatus;
    ErrorMsg: string;
  end;

  function GetFileMark(const FileName: string): string; //26082019095112WMSP
  var Len: Integer;
  begin
  Result:='';
  Len:=Length(C_DATETIME_MASK+C_MODIFICATION_MARK);
  try
  with TFileStream.Create(FileName, fmShareDenyNone) do
   try
   if Size>Len then
    begin
    Seek(-Len, soFromEnd);
    SetLength(Result, Len);
    ReadBuffer(Pointer(Result)^, Len);
    Result:=ReverseString(Result);
    end;
   finally
   Free;
   end;
  except
  Result:='';
  end;
  end;

  function GetFileSize(const FileName: string): Integer; //125235 byte
  begin
  try
  with TFileStream.Create(FileName, fmShareDenyNone) do
   try
   Result:=Size;
   finally
   Free;
   end;
  except
  Result:=-1;
  end;
  end;

  //Numbers=[1,6,0,1]; Text="1.6.0.1"; Count=4; ID=1242
  function GetXMLVersion(const FileName: string): RVersion;
  var SList: TStringList;
      i: Integer;
      Str: string;
  begin
  with Result do
   begin
   Count:=0;
   SetLength(Numbers, Count);
   Text:='';
   ID:=0;
   end;
  if FileExists(FileName) then
   begin
   SList:=TStringList.Create;
   try
   SList.LoadFromFile(FileName);
   if SList.Count>1 then
    begin
    i:=Pos('v.', SList.Text); //<version>v.1.6.0.2 #1423</version>
    if i>0 then
     begin
     Result.Text:=RightStr(SList.Text, Length(SList.Text)-2-(i-1));
     i:=Pos('</', Result.Text);
     if i>0 then
      begin
      Result.Text:=Trim(LeftStr(Result.Text, i-1)); //1.6.0.2 #1423
      SList.QuoteChar:=#0;
      SList.Delimiter:='#';
      SList.DelimitedText:=Result.Text;
      if SList.Count>1 then
       Result.ID:=StrToIntDef(SList.Strings[1], 0);
      Str:=SList.Strings[0];
      SList.Delimiter:='.';
      SList.DelimitedText:=Str;
      for i:=0 to SList.Count-1 do
       begin
       Inc(Result.Count);
       SetLength(Result.Numbers, Result.Count);
       Result.Numbers[i]:=StrToIntDef(SList.Strings[i], 0);
       end;
      end
     else Result.Text:='';
     end;
    end;
   finally
   SList.Free;
   end;
   end;
  end;

  //Numbers=[1,6,0,280]; Text="1.6.0.280"; Count=4; ID=123232
  function GetFileVersion(const FileName: string): RVersion;
  var PInfo, PLang: Pointer;
      lpdwHandle, InfoSize, FileInfoSize: Cardinal;
      FileInfo: PVSFixedFileInfo;
      TranslationString: string;
      FileVersionText: PChar;
  begin
  with Result do
   begin
   Count:=0;
   SetLength(Numbers, Count);
   Text:='';
   end;
  try
  InfoSize:=GetFileVersionInfoSize(PChar(FileName), lpdwHandle);
  if InfoSize<>0 then
   begin
   GetMem(PInfo, InfoSize);
   try
   if GetFileVersionInfo(PChar(FileName), lpdwHandle, InfoSize, PInfo) then
    begin
    if VerQueryValue(PInfo, '\', Pointer(FileInfo), FileInfoSize)and(FileInfoSize>0) then
     with Result do //FILEVERSION 1,6,0,280
      begin
      Count:=4;
      SetLength(Numbers, Count);
      Numbers[0]:=FileInfo.dwFileVersionMS shr 16;
      Numbers[1]:=FileInfo.dwFileVersionMS and $FFFF;
      Numbers[2]:=FileInfo.dwFileVersionLS shr 16;
      Numbers[3]:=FileInfo.dwFileVersionLS and $FFFF;
      Text:=Format('%d.%d.%d.%d', [Numbers[0], Numbers[1], Numbers[2], Numbers[3]]);
      end;
    if VerQueryValue(PInfo, '\VarFileInfo\Translation', PLang, FileInfoSize)and(FileInfoSize>0) then
     begin //VALUE "Translation", 0x0000 0x04B0
     TranslationString:=IntToHex(MakeLong(HiWord(Longint(PLang^)), LoWord(Longint(PLang^))), 8);
     if VerQueryValue(PInfo, PChar('StringFileInfo\'+TranslationString+'\FileVersion'), Pointer(FileVersionText), FileInfoSize)and(FileInfoSize>0) then
      begin //VALUE "FileVersion", "1.6.0.280 #1198938"
      Result.Text:=FileVersionText;
      if Pos('#', FileVersionText)>0 then
       Result.ID:=StrToIntDef(RightStr(Result.Text, Length(Result.Text)-1-(Pos('#', FileVersionText)-1)), 0);
      end;
     end;
    end;
   finally
   FreeMem(PInfo);
   end;
   end;
  except
  end;
  end;

  //Numbers=[1,6,0,0]; Text="1.6.0.0"; Count=4; ID=0
  function GetProductVersion(const FileName: string): RVersion;
  var PInfo: Pointer;
      lpdwHandle, InfoSize, FileInfoSize: Cardinal;
      FileInfo: PVSFixedFileInfo;
  begin
  with Result do
   begin
   Count:=0;
   SetLength(Numbers, Count);
   Text:='';
   end;
  try
  InfoSize:=GetFileVersionInfoSize(PChar(FileName), lpdwHandle);
  if InfoSize<>0 then
   begin
   GetMem(PInfo, InfoSize);
   try
   if GetFileVersionInfo(PChar(FileName), lpdwHandle, InfoSize, PInfo) then
    if VerQueryValue(PInfo, '\', Pointer(FileInfo), FileInfoSize)and(FileInfoSize>0) then
     with Result do //PRODUCTVERSION 1,6,0,0
      begin
      Count:=4;
      SetLength(Numbers, Count);
      Numbers[0]:=FileInfo.dwProductVersionMS shr 16;
      Numbers[1]:=FileInfo.dwProductVersionMS and $FFFF;
      Numbers[2]:=FileInfo.dwProductVersionLS shr 16;
      Numbers[3]:=FileInfo.dwProductVersionLS and $FFFF;
      Text:=Format('%d.%d.%d.%d', [Numbers[0], Numbers[1], Numbers[2], Numbers[3]]);
      end;
   finally
   FreeMem(PInfo);
   end;
   end;
  except
  end;
  end;

  function DownloadSignsText(): string;
  var hSession, hUrl: HInternet;
      Header: TStringStream;
      BlockSize, BlockLen: Cardinal;
      i, HeaderLength: Integer;
      Buffer: string;
      Error: Boolean;
  begin
  Result:='';
  hSession:=InternetOpen(nil, INTERNET_OPEN_TYPE_PRECONFIG, nil, nil, 0);
  if Assigned(hSession) then
   try
   //-------------- Settings --------------
   Header:=TStringStream.Create('');
   try
   with Header do
    begin
    WriteString('User-Agent: ' + C_USER_AGENT_DEFAULT   + #13#10);
    WriteString('Accept: '     + C_CONTENT_TYPE_DEFAULT + #13#10);
    end;
   HeaderLength:=Length(Header.DataString);
   //-------------- Download --------------
   i:=1;
   Error:=True;
   while Error and (i<4) do
    try
    hUrl:=InternetOpenUrl(hSession, PChar(C_SIGNATURELIST_URL), PChar(Header.DataString), HeaderLength,
                          INTERNET_FLAG_RELOAD or INTERNET_FLAG_NO_CACHE_WRITE or INTERNET_FLAG_KEEP_CONNECTION, 0);
    if not Assigned(hUrl) then
     raise Exception.Create('');
    InternetQueryDataAvailable(hUrl, BlockSize, 0, 0);
    while BlockSize>0 do
     begin
     SetLength(Buffer, BlockSize);
     if not InternetReadFile(hUrl, @Buffer[1], BlockSize, BlockLen)or(BlockLen=0) then
      Break;
     Result:=Result+Buffer;
     InternetQueryDataAvailable(hUrl, BlockSize, 0, 0);
     end;
    if Length(Result)=0 then
     raise Exception.Create('');
    Error:=False;
    except
    Inc(i);
    if i=4 then Break
    else Sleep(C_ATTEMPTS_TIMEOUT);
    end;
   finally
   Header.Free;
   end;
   finally
   InternetCloseHandle(hSession);
   end
  end;

  function SearchNearestSign(const SignsText: string; const XmlVersion, ExeFileVersion: RVersion): RSign;
    //"1.6.0" -> [1,6,0]
    function ParseNumbers(const Text: string; var Numbers: AInteger): Integer;
    var i: Integer;
        Str: string;
    begin
    Result:=0;
    SetLength(Numbers, 0);
    if Length(Text)>0 then
     begin
     Str:='';
     for i:=1 to Length(Text) do
      if Text[i]='.' then
       begin
       SetLength(Numbers, Result+1);
       Numbers[Result]:=StrToIntDef(Str, 0);
       Str:='';
       Inc(Result);
       end
      else Str:=Str+Text[i];
     if Length(Str)>0 then
      begin
      SetLength(Numbers, Result+1);
      Numbers[Result]:=StrToIntDef(Str, 0);
      Inc(Result);
      end;
     end;
    end;

    function ParseBytes(const HexList: string; var Sign: AHex): Integer;
    var i: Integer;
        Str: string;
    begin
    Result:=0;
    SetLength(Sign, 0);
    if Length(HexList)>0 then
     begin
     Str:='';
     for i:=1 to Length(HexList) do
      if HexList[i] in [' ', #9] then
       begin
       if Length(Str)>0 then
        begin
        SetLength(Sign, Result+1);
        Sign[Result].Any:=SameText('XX', Str);
        if not Sign[Result].Any then
         Sign[Result].Byte:=StrToIntDef('$'+Str, 0);
        Str:='';
        Inc(Result);
        end;
       end
      else Str:=Str+HexList[i];
     if Length(Str)>0 then
      begin
      SetLength(Sign, Result+1);
      Sign[Result].Any:=SameText('XX', Str);
      if not Sign[Result].Any then
       Sign[Result].Byte:=StrToIntDef('$'+Str, 0);
      Inc(Result);
      end;
     end;
    end;

    //A>B=1, (A=B)=0, A<B=-1
    function CompareNumbers(const NumbersA, NumbersB: AInteger): Integer;
    var i, LenA, LenB, LenMax: Integer;
    begin
    Result:=0;
    LenA:=Length(NumbersA);
    LenB:=Length(NumbersB);
    if LenA>LenB then LenMax:=LenA
    else LenMax:=LenB;
    for i:=0 to LenMax-1 do
     if LenA=i then
      begin
      Result:=-1;
      Break;
      end
     else if LenB=i then
           begin
           Result:=1;
           Break;
           end
          else if NumbersA[i]>NumbersB[i] then
                 begin
                 Result:=1;
                 Break;
                 end
               else if NumbersA[i]<NumbersB[i] then
                     begin
                     Result:=-1;
                     Break;
                     end;
    end;

  var SignsTextList, ValueList: TStringList;
      SignsList: array of RSign;
      Str: string;
      isHexList: Boolean;
      i,j,k: Integer;
  begin
  with Result do
   begin
   SetLength(OldSign, 0);
   SetLength(NewSign, 0);
   end;
  SetLength(SignsList, 0);
  SignsTextList:=TStringList.Create;
  ValueList:=TStringList.Create;
  try
  SignsTextList.Text:=SignsText;
  for i:=0 to SignsTextList.Count-1 do
   begin
   Str:=Trim(SignsTextList.Strings[i]);
   if (Str='')or(Str[1]='#') then
    Continue;
   //-------------- String parsing --------------
   ValueList.Clear();
   ValueList.Append('');
   isHexList:=False;
   k:=0;
   for j:=1 to Length(Str) do
    if not isHexList and (Str[j] in [' ', #9]) then
     begin
     if ValueList.Strings[ValueList.Count-1]<>'' then
      begin
      ValueList.Append('');
      Inc(k);
      end;
     end
    else case Str[j] of
         '#': Break;
         '[': isHexList:=True;
         ']': isHexList:=False;
         else ValueList.Strings[k]:=ValueList.Strings[k]+Str[j];
         end;
   //-------------- Convert values to RSign --------------
   if ValueList.Count>=6 then
    begin
    j:=Length(SignsList);
    SetLength(SignsList, j+1);
    SignsList[j].XmlVersion.Text:=ValueList.Strings[0];
    SignsList[j].XmlVersion.Count:=ParseNumbers(SignsList[j].XmlVersion.Text, SignsList[j].XmlVersion.Numbers);
    if ValueList.Strings[1]<>'-' then
     begin
     SignsList[j].ExeVersion.Text:=ValueList.Strings[1];
     SignsList[j].ExeVersion.Count:=ParseNumbers(SignsList[j].ExeVersion.Text, SignsList[j].ExeVersion.Numbers);
     if ValueList.Strings[2]<>'-' then
      SignsList[j].ExeVersion.ID:=StrToIntDef(ValueList.Strings[2], 0)
     else SignsList[j].ExeVersion.ID:=0;
     end
    else begin
         SignsList[j].ExeVersion.Text:='';
         SignsList[j].ExeVersion.Count:=0;
         SetLength(SignsList[j].ExeVersion.Numbers, 0);
         SignsList[j].ExeVersion.ID:=0;
         end;
    ParseBytes(ValueList.Strings[3], SignsList[j].OldSign);
    ParseBytes(ValueList.Strings[4], SignsList[j].NewSign);
    SignsList[j].EntryNumber.All:=(ValueList.Strings[5]='-');
    if not SignsList[j].EntryNumber.All then
     SignsList[j].EntryNumber.Number:=StrToIntDef(ValueList.Strings[5], 1);
    end
   else Continue;
   end;
  finally
  ValueList.Free;
  SignsTextList.Free;
  end;
  //-------------- Signatures comparison --------------
  if Length(SignsList)>0 then
   begin
   i:=0;
   while i<Length(SignsList) do
    try
    if SignsList[i].XmlVersion.Count=0 then Continue;
    j:=CompareNumbers(SignsList[i].XmlVersion.Numbers, XmlVersion.Numbers);
    if j=-1 then Continue
    else if j=1 then begin
                     if i<>0 then
                      Result:=SignsList[i-1]; //Previous sign
                     Exit;
                     end;
    //--------------
    if SignsList[i].ExeVersion.Count=0 then Continue;
    j:=CompareNumbers(SignsList[i].ExeVersion.Numbers, ExeFileVersion.Numbers);
    if j=-1 then Continue
    else if j=1 then begin
                     if i<>0 then
                      Result:=SignsList[i-1]; //Previous sign
                     Exit;
                     end;
    //--------------
    if SignsList[i].ExeVersion.ID=0 then Continue;
    if SignsList[i].ExeVersion.ID<ExeFileVersion.ID then Continue
    else if SignsList[i].ExeVersion.ID>ExeFileVersion.ID then
          begin
          if i<>0 then
           Result:=SignsList[i-1]; //Previous sign
          Exit;
          end;
    Break; //Complete match
    finally
    Inc(i);
    end;
   Result:=SignsList[i-1]; //Last sign in list or the current sign if match is completed
   end;
  end;

  function ReplaceSignInFile(const FileName: string; const Sign: RSign): RReplaceResult;
    function CreateBackup(const FileName: string): Boolean;
    var NewName: string;
    begin
    Result:=FileExists(FileName);
    if Result then
     try
     NewName:=FileName+'.backup';
     if FileExists(NewName) then
      Result:=DeleteFile(NewName);
     if Result then
      Result:=RenameFile(FileName, NewName);
     except
     Result:=False;
     end;
    end;

  var F: file;
      i,j, LenMax, MatchNumber: Integer;
      Buffer: AByte;
      Coincided, Replaced: Boolean;
      Str: string;

  begin
  with Result do
   begin
   Status:=StNotFound;
   ErrorMsg:='';
   end;
  if FileExists(FileName) then
   try
   AssignFile(F, FileName);
   Reset(F, 1);
   try
   SetLength(Buffer, FileSize(F));
   if Length(Buffer)>0 then
    BlockRead(F, Buffer[0], Length(Buffer));
   finally
   CloseFile(F);
   end;
   if Length(Buffer)>0 then
    begin
    i:=0;
    Replaced:=False;
    MatchNumber:=0;
    if Length(Sign.OldSign)>Length(Sign.NewSign) then
     LenMax:=Length(Sign.OldSign)
    else LenMax:=Length(Sign.NewSign);
    while i<(Length(Buffer)-LenMax-1) do
     begin
     Coincided:=True;
     for j:=0 to Length(Sign.OldSign)-1 do
      if not Sign.OldSign[j].Any and (Buffer[i+j]<>Sign.OldSign[j].Byte) then
       begin
       Coincided:=False;
       Break;
       end;
     if Coincided then
      begin
      Inc(MatchNumber);
      if (Sign.EntryNumber.All)or(Sign.EntryNumber.Number=MatchNumber) then
       begin
       for j:=0 to Length(Sign.NewSign)-1 do
        if not Sign.NewSign[j].Any then
         Buffer[i+j]:=Sign.NewSign[j].Byte;
       if not Replaced then
        Replaced:=True;
       if not Sign.EntryNumber.All then
        Break;
       Inc(i, LenMax-1);
       end;
      end;
     Inc(i);
     end;
    if Replaced then
     begin
     if V_ARG_CREATE_BACKUP then
      if not CreateBackup(FileName) then
       begin
       Result.Status:=StNotBackup;
       Exit;
       end;
     ReWrite(F, 1);
     try
     Seek(F, 0);
     BlockWrite(F, Buffer[0], Length(Buffer));
     if V_ARG_ADD_MARK then
      begin
      DateTimeToString(Str, C_DATETIME_MASK, Now());
      Str:=ReverseString(C_MODIFICATION_MARK+Str); //WMSP26082019095112 -> 21159091028062PSMW
      BlockWrite(F, Str[1], Length(Str));
      end;
     finally
     CloseFile(F);
     end;
     Result.Status:=StOK;
     end;
    SetLength(Buffer, 0);
    Buffer:=nil;
    end;
   except
   on E: Exception do
    with Result do
     begin
     Status:=StError;
     ErrorMsg:=E.Message;
     end;
   end;
  end;

const
  C_H_PREFIX = '  > ';
  C_S_PREFIX = '    ';
  C_L_PREFIX = '          ';

var i,j: Integer;
    Str, XMLFileName, ExeFileName, SignsText: string;
    XmlVersion, ExeProductVersion, ExeFileVersion: RVersion;
    Sign: RSign;
    ReplaceResult: RReplaceResult;

begin
Writeln(Format(C_APP_HEADER, [C_APP_VERSION, C_APP_DATE]));
Writeln('');

//------------- Parsing command line arguments -------------

for i:=1 to ParamCount do
 begin
 j:=Pos(C_ARG_WOT_PATH_WIN32, ParamStr(i));
 if j>0 then
  begin
  V_ARG_WOT_PATH:=ParamStr(i);
  V_ARG_WOT_PATH:=Trim(RightStr(V_ARG_WOT_PATH, Length(V_ARG_WOT_PATH)-Length(C_ARG_WOT_PATH_WIN32)-(j-1)));
  end;
 if Pos(C_ARG_SILENT_MODE_WIN32, ParamStr(i))>0 then V_ARG_SILENT_MODE:=True;
 if Pos(C_ARG_CREATE_BACKUP_WIN32, ParamStr(i))>0 then V_ARG_CREATE_BACKUP:=False;
 if Pos(C_ARG_ADD_MARK_WIN32, ParamStr(i))>0 then V_ARG_ADD_MARK:=False;
 end;
if Length(V_ARG_WOT_PATH)>0 then
 begin
 if V_ARG_WOT_PATH[Length(V_ARG_WOT_PATH)]<>'\' then
  V_ARG_WOT_PATH:=V_ARG_WOT_PATH+'\';
 if not DirectoryExists(V_ARG_WOT_PATH) then
  V_ARG_WOT_PATH:='';
 end;
if Length(V_ARG_WOT_PATH)=0 then
 V_ARG_WOT_PATH:=ExtractFilePath(ParamStr(0));

//-------------- Search and analysis of game files ------------------

Write(C_H_PREFIX+'Game client exe-file search... ');
Str:=LowerCase(ExtractFileName(LeftStr(V_ARG_WOT_PATH, Length(V_ARG_WOT_PATH)-1)));
if Pos({$IFDEF WOT32}C_WOT64EXE_FOLDER{$ELSE}C_WOT32EXE_FOLDER{$ENDIF}, Str)>0 then
 begin
 Writeln('error!');
 Writeln('');
 {$IFDEF WOT32}
 Write(C_S_PREFIX+'Program does not work with the x64-file. Press enter to exit...');
 {$ELSE}
 Write(C_S_PREFIX+'Program does not work with the x32-file. Press enter to exit...');
 {$ENDIF}
 if not V_ARG_SILENT_MODE then Readln;
 Halt(ERROR_XBIT);
 end;
if Pos({$IFDEF WOT32}C_WOT32EXE_FOLDER{$ELSE}C_WOT64EXE_FOLDER{$ENDIF}, Str)>0 then
 begin
 ExeFileName:=V_ARG_WOT_PATH+'WorldOfTanks.exe'; //Old version
 V_ARG_WOT_PATH:=ExtractFilePath(ExtractFileDir(ExeFileName));
 end
else if DirectoryExists(V_ARG_WOT_PATH+{$IFDEF WOT32}C_WOT32EXE_FOLDER{$ELSE}C_WOT64EXE_FOLDER{$ENDIF}) then
      ExeFileName:=V_ARG_WOT_PATH+{$IFDEF WOT32}C_WOT32EXE_FOLDER{$ELSE}C_WOT64EXE_FOLDER{$ENDIF}+'\WorldOfTanks.exe'
     else ExeFileName:='';
if FileExists(ExeFileName) then
 begin
 i:=Length(C_MODIFICATION_MARK);
 Str:=GetFileMark(ExeFileName);
 if Length(Str)>0 then
  if LeftStr(Str,i)=C_MODIFICATION_MARK then
   begin
   Str:=Copy(Str, i+1, Length(C_DATETIME_MASK));
   Str:=Format('[%s/%s/%s %s:%s:%s]', [Copy(Str,1,2), Copy(Str,3,2), Copy(Str,5,4), Copy(Str,9,2), Copy(Str,11,2), Copy(Str,13,2)]);
   Writeln('already patched! '+Str);
   Writeln('');
   Write(C_S_PREFIX+'Press enter to exit...');
   if not V_ARG_SILENT_MODE then Readln;
   Halt(ERROR_ALREADY_PATCHED);
   end
  else Writeln('OK')
 else begin
      Writeln('error!');
      Writeln('');
      Write(C_S_PREFIX+'Game exe-file unavailable or corrupted. Press enter to exit...');
      if not V_ARG_SILENT_MODE then Readln;
      Halt(ERROR_WOTEXE_INVALID);
      end;
 end
else begin
     Writeln('not found!');
     Writeln('');
     Write(C_S_PREFIX+'Copy the program to the game folder. Press enter to exit...');
     if not V_ARG_SILENT_MODE then Readln;
     Halt(ERROR_WOTEXE_NOTFOUND);
     end;
Writeln('');
XMLFileName:=V_ARG_WOT_PATH+'version.xml';
Writeln(C_S_PREFIX+'File: '+XMLFileName);
if FileExists(XMLFileName) then
 begin
 XmlVersion:=GetXMLVersion(XMLFileName);
 if XmlVersion.Count>0 then
  Writeln(C_L_PREFIX+'Version: '+XmlVersion.Text)
 else Writeln(C_L_PREFIX+'Version: not decoded!');
 end
else Writeln(C_L_PREFIX+'Version: not found!');
Writeln('');
Writeln(C_S_PREFIX+'File: '+ExeFileName);
ExeFileVersion:=GetFileVersion(ExeFileName);
if ExeFileVersion.Count>0 then
     Writeln(C_L_PREFIX+'FileVersion:    '+ExeFileVersion.Text)
else Writeln(C_L_PREFIX+'FileVersion:    not decoded!');
ExeProductVersion:=GetProductVersion(ExeFileName);
if ExeProductVersion.Count>0 then
     Writeln(C_L_PREFIX+'ProductVersion: '+ExeProductVersion.Text)
else Writeln(C_L_PREFIX+'ProductVersion: not decoded!');
Writeln(C_L_PREFIX+Format('FileSize:       %d', [GetFileSize(ExeFileName)]));
if (ExeFileVersion.Count=0)or(ExeProductVersion.Count=0) then
 begin
 Writeln('');
 Write(C_S_PREFIX+'Program could not get information. Press enter to exit...');
 if not V_ARG_SILENT_MODE then Readln;
 Halt(ERROR_WOTVERSION_NOTFOUND);
 end;
if XmlVersion.Count=0 then
 XmlVersion:=ExeProductVersion;

//-------------- Signature list download ------------------

Writeln('');
Write(C_H_PREFIX+'Signatures loading... ');
SignsText:='';
if FileExists(ExtractFilePath(ParamStr(0))+C_SIGNATURES_FILENAME) then
 try
 with TFileStream.Create(C_SIGNATURES_FILENAME, fmShareDenyNone) do
  try
  SetLength(SignsText, Size);
  Read(Pointer(SignsText)^, Size);
  finally
  Free;
  end;
 except
 SignsText:='';
 end;
if Length(SignsText)>0 then
 Writeln('OK [from Local]')
else begin
     Writeln('not found!');
     Writeln('');
     if not V_ARG_SILENT_MODE then
      begin
      Write(C_S_PREFIX+'Download signatures from the site? [Press Y/N and ENTER] ');
      Readln(Str);
      if not SameText(Str, 'Y') then Halt
      else Writeln('');
      end;
     Write(C_H_PREFIX+'Signatures downloading... ');
     SignsText:=DownloadSignsText();
     if Length(SignsText)>0 then
      Writeln('OK [from Repo]')
     else begin
          Writeln('not found!');
          Writeln('');
          Write(C_S_PREFIX+'Check file availability in repository. Press enter to exit...');
          if not V_ARG_SILENT_MODE then Readln;
          Halt(ERROR_REPO_NOTFOUND);
          end;
     end;

//-------------- Search for a suitable signature ------------------

Writeln('');
Write(C_H_PREFIX+'Nearest signature search... ');
Sign:=SearchNearestSign(SignsText, XmlVersion, ExeFileVersion);
if Length(Sign.OldSign)>0 then
 begin
 Writeln('OK');
 Writeln('');
 Writeln(C_S_PREFIX+'Signature parameters');
 Writeln(C_L_PREFIX+'ClientVersion: '+Sign.XmlVersion.Text);
 if Length(Sign.ExeVersion.Text)>0 then
  if Sign.ExeVersion.ID>0 then
       Writeln(C_L_PREFIX+'FileVersion:   '+Sign.ExeVersion.Text+' #'+IntToStr(Sign.ExeVersion.ID))
  else Writeln(C_L_PREFIX+'FileVersion:   '+Sign.ExeVersion.Text)
 else  Writeln(C_L_PREFIX+'FileVersion:   -');
 end
else begin
     Writeln('not found!');
     Writeln('');
     Write(C_S_PREFIX+'Could not find a suitable signature. Press enter to exit...');
     if not V_ARG_SILENT_MODE then Readln;
     Halt(ERROR_SIGN_NOTFOUND);
     end;

//-------------- File modification ------------------

Writeln('');
if not V_ARG_SILENT_MODE then
 begin
 Write(C_S_PREFIX+'Patch the game exe-file? [Press Y/N and ENTER] ');
 Readln(Str);
 if not SameText(Str, 'Y') then Halt;
 end;
Writeln('');
Write(C_H_PREFIX+'File "WorldOfTanks.exe" modification... ');
ReplaceResult:=ReplaceSignInFile(ExeFileName, Sign);
case ReplaceResult.Status of
StOK: begin
      Writeln('OK');
      Writeln('');
      Write(C_S_PREFIX+'Press enter to exit...');
      end;
StNotFound: begin
            Writeln('not found!');
            Writeln('');
            Write(C_S_PREFIX+'Could not find match with signature in game file, maybe the file is already patched or not included in the list of signatures. Press enter to exit...');
            end;
StNotBackup: begin
             Writeln('canceled!');
             Writeln('');
             Write(C_S_PREFIX+'Unable to create backup-file, no access. Press enter to exit...');
             end;
else begin
     Writeln('error!');
     Writeln('');
     if Length(ReplaceResult.ErrorMsg)>0 then
      begin
      if ReplaceResult.ErrorMsg[Length(ReplaceResult.ErrorMsg)]<>'.' then
       ReplaceResult.ErrorMsg:=ReplaceResult.ErrorMsg+'.';
      Write(C_S_PREFIX+ReplaceResult.ErrorMsg+' Press enter to exit...');
      end
     else Write(C_S_PREFIX+'Press enter to exit...');
     end;
end;
if not V_ARG_SILENT_MODE then
 Readln;
end.
