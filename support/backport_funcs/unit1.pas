unit Unit1;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,strutils;

const
   // InstrEx mode flags
   isForward  = 0;
   isBackward = 1;
   isNumber   = 2;
   isNoCase   = 4;


type

  { TForm1 }

  TForm1 = class(TForm)
    Button1: TButton;
    Button2: TButton;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    ListBox1: TListBox;
    ListBox2: TListBox;
    Memo1: TMemo;
    Memo2: TMemo;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);

  private
    function ExtractFunction(fname:String):String;
    function ExistsInB(fname:string): boolean;
    function ParseFile(fname:String; lb: TListBox):string;
    function InStrEx(StartPos: Integer; SourceString: String;
                 SearchString: String; SearchMode:Integer = isForward;
                 OrdSelector: Integer=0):Integer;
  public
    { public declarations }
  end;


var
  Form1: TForm1;
  hookSrc: String;

implementation

{$R *.lfm}

{ TForm1 }
function TForm1.ExtractFunction(fname:String):String;
var
   sl: TStringList;
   a,b:integer;
begin
     if length(hookSrc) = 0 then begin
        sl := TStringList.Create;
        sl.LoadFromFile('userhooks.cpp');
        hookSrc := sl.Text;
        sl.Free;
     end;

     a := InstrEx(0, hookSrc, fname);
     if a = -1 then exit;

     a := InstrEx(a,hookSrc, #10, isBackward);
     if a = -1 then exit;

     b := InstrEx(a, hookSrc, #10+'}');
     if b = -1 then exit;

     result := MidStr(hookSrc, a, b-a+2);

end;

function TForm1.ParseFile(fname:String; lb: TListBox):String;
var
 File1: TextFile;
 Str: String;
 a,b: integer ;
 tmp: String;

begin
  AssignFile(File1, fname);
  {$I+}
  try
    Reset(File1);
    repeat
      tmp := '';
      Readln(File1, Str);          // Reads the whole line from the file
      a := InstrEx(0, str, 'hook_');
      if a > 0 then {a += length('hook_');} b:= InstrEx(a, str, '(');
      if b > 0 then tmp := MidStr(str, a, b-a);
      if length(tmp) > 0 then lb.AddItem(tmp, nil);

    until(EOF(File1));
    CloseFile(File1);
  except
    on E: EInOutError do
    begin
     ShowMessage('File handling error occurred. Details: '+E.ClassName+'/'+E.Message);
    end;
  end;

  Result := IntToStr(lb.Count);


end;

function TForm1.ExistsInB(fname:string): boolean;
var
  a: integer;
  val: string;
begin

  for a:=0 to listbox2.count-1 do
  begin
      val := listbox2.Items.Strings[a];
      if val = fname then begin
         result := true;
         exit;
      end;

  end;

  result := false;
end;

procedure TForm1.Button1Click(Sender: TObject);
var
  a,b:integer;
  ret: string;
  val: string;
  funcs: string;
begin
  label1.Caption := ParseFile('Windows.txt', ListBox1);
  label2.Caption := ParseFile('Linux.txt', ListBox2);

  ret := '';
  funcs := '';
  //ShowMessage( IntToStr(listbox1.count) );

  for a:=0 to listbox1.count-1 do
  begin
     val := listbox1.Items.Strings[a];
     {if ListBox2.Items.IndexOf(val) >= 0 then begin}  //this didnt work as expected ?
      if not ExistsInB(val) then begin
        ret += val + #13 ;
        funcs += ExtractFunction(val) + #13#10#13#10;
        inc(b);
     end;
  end;

  Memo2.Text := funcs;
  Memo1.Text := ret;
  label3.Caption := inttostr(b);

end;

procedure TForm1.Button2Click(Sender: TObject);
var
  test: string;
  a,b:integer;
  sl:TStringList;
begin
   test := 'this is a test'+#13+'and some more';

   Memo2.Text := ExtractFunction('hook_');


end;



// InStrEx
// Replacement function for Pos().  It includes both the VB Instr and InstrRev functions.

// Synopsis:
// InStrEx(StartPos: Integer;
//         SourceString: String;
//         SearchString: String;
//         SearchMode:   Integer;
//         OrdSelector:  Integer): Integer
//
//         StartPos    : The character position from where the search
//                       begins (1 = first character of SourceString, etc.)
//                       Zero (0) would signify the search starts at the beginning of the string.
//
//         SourceString: String expression being searched.
//
//         SearchString: String expression sought.
//
//         SearchMode  : Range of flags specified by the following constants.
//
//                       isForward : Specifies forward search through the SourceString.
//
//                       isBackward: Specifies backward search through the SourceString.
//
//                       isNumber  : Instructs the function to find the NUMBER of occurrences
//                                   of SearchString within SourceString, starting from StartPos,
//                                   and searching in the relevant direction.
//
//                       isNoCase  : if added to any combination of the above, specifies the
//                                   search be performed as case INSENSITIVE. Case sensitive
//                                   is the default.
//
//                       These constants are added together bitwise using 'OR' to combine
//                       modes (e.g., isBackward or isNumber will search backwards from
//                       StartPos, and count how many occurrences of SearchString it has
//                       found in SourceString.  If no further occurrences of SearchString
//                       are found from the chosen search point, then InStrEx() returns zero.
//
//         OrdSelector : Specifies which occurrence of SearchString is to be searched for.
//                       When not used, it should be set to zero.  NOTE: This flag is not
//                       valid when used in conjunction with isNumber.)
//
//  http://www.vincenzo.net/isxkb/index.php?title=Instr_for_Pascal

function TForm1.InStrEx(StartPos: Integer; SourceString: String;
                 SearchString: String; SearchMode:Integer = isForward;
                 OrdSelector: Integer=0):Integer;

var
z:           Integer;
cn:          Integer;
ChrStepping: Integer;
ChrFrom:     Integer;
ChrTo:       Integer;
tmpStr1:     String;
tmpStr2:     String;
Str1:        String;

begin
   If SourceString <> '' then begin

      // Create temp copies of our source and search strings.
      tmpStr1 := SourceString ;
      tmpStr2 := SearchString ;

      Result := 0 ;

      // Just in case the dev (you know, you) forgets to specify either isForward
      // or isBackward when specifying other flags.
      If (SearchMode and isBackward) = 0 then begin
         SearchMode := SearchMode or isForward;
      end;

      // This conditional test checks to see if bit 2 of IS_Mode (corresponding to
      // a value of 4) is set. If it is, then we've selected no case sensitivity.

      // To make a case insensitive search, make our temp strings all uppercase.
      If (SearchMode and isNoCase) <> 0 then begin
         tmpStr1 := UpperCase(tmpStr1);
         tmpStr2 := UpperCase(tmpStr2);
      end;

      // This is a check to see if user has entered a nonsensical value for the
      // ordinal selector. If so, set it to a default value of 1 initially,
      // then correct the value because, for the first search, it actually needs
      // to be zero (and so on for the other values ... N-1)
      cn := OrdSelector;
      If cn = 0 then begin
         cn := 1;
      end;

      cn := cn - 1;

      // This select checks the lowest bit position only (i.e., bit 0). If it's set,
      // then we're searching backwards, otherwise we're searching forwards.
      case (SearchMode and $00000001) of
         isForward:
            begin
               If StartPos = 0 then begin
                  StartPos := 1;
               end;
               ChrFrom := StartPos;
               ChrTo := Length(tmpStr1);

               // Now actually start searching for our string!
               // This For/Loop counts up, as we are searching forward in our string.
               For z := ChrFrom to ChrTo do begin

                  // Grabs the character(s) of the string based on it's position in the loop.
                  Str1 := Copy(tmpStr1, z, Length(tmpStr2));

                  // Compare those characters to the temp search string.
                  If Str1 = tmpStr2 then begin

                     // If checking for instance count of the search string, add it!
                     // If not, return the count of the loop, which is the position of the first
                     // occurrence from the StartPos.
                     If (SearchMode and isNumber) <> 0 then begin
                        Result := Result + 1;
                     end else begin
                        Result := z;

                        // If we are not dealing with the ordinal option, exit the function.
                        // Otherwise add one to the ordinal count.
                        If cn = 0 then begin
                           exit;
                        end else begin
                           cn := cn - 1;
                        end;
                     end;
                  end;
               end;
            end;

         // The same comments above apply below for isBackwards, except where noted.
         isBackward:
            begin
               If StartPos = 0 then begin
                  StartPos := Length(tmpStr1);
               end;

               ChrFrom := StartPos;
               ChrTo := 1;

               // This For/Loop counts down, as we are searching backward in our string.
               For z := ChrFrom downto ChrTo do begin
                  Str1 := Copy(tmpStr1, z, Length(tmpStr2));

                  If Str1 = tmpStr2 then begin
                     If (SearchMode and isNumber) <> 0 then begin
                        Result := Result + 1;
                     end else begin

                        // Since Pascal does not have the Step keyword in For loops, and since
                        // the loop count counts down from the length of the SourceString, we must
                        // compensate for the accurate number of chars counting backwards.  We do
                        // this by subtracting the loop count from the total number of characters
                        // of the SourceString, plus the length of the SearchString characters.
                        {Result := (ChrFrom - z) + Length(tmpStr2);}

                        //dz- i want absolute position not relative..
                        Result := z - Length(tmpStr2);

                        If cn = 0 then begin
                           exit;
                        end else begin
                           cn := cn - 1;
                        end;
                     end;
                  end;
               end;
            end;
      end;

      // If we're simply performing a forward or backward search, and we reach
      // the end of the loop, then we've scanned the entire SourceString, and not
      // found the specified occurrence of the SearchString. So, we need to signal
      // this fact by returning the special value -1.
      If (SearchMode and isNumber) = 0 then begin
         Result := -1;
      end;
   end;
end;

end.

