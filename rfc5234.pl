/*

   Copyright (c) 2020 Eric G. Taucher

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this
      list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

:- module(rfc5234,
    [
        alpha//1,
        alternation//1,
        'bin_digit*'//1,
        'bin_digit+'//1,
        binval//1,
        bit//1,
        bit//1,
        char//1,
        charval//1,
        cnl//1,
        comment//1,
        concatenation//1,
        cr//1,
        crlf//1,
        ctl//1,
        cwsp//1,
        decval//1,
        defined_as//1,
        dec_to_bin/2,
        dec_to_hex/2,
        digit//1,
        'digit*'//1,
        'digit+'//1,
        dquote//1,
        element//1,
        elements//1,
        fixed_point_check/1,
        group//1,
        'hex_digit*'//1,
        'hex_digit+'//1,
        hexdig//1,
        hexdig//1,
        hexval//1,
        htab//1,
        htab//1,
        lf//1,
        lwsp//1,
        numval//1,
        octet//1,
        option//1,
        parse/2,
        proseval//1,
        recognize/1,
        repeat//1,
        repetition//1,
        rule//1,
        'rulelist*'//1,
        'rulelist+'//1,
        rulelist//1,
        rulename//1,
        sp//1,
        vchar//1,
        'wsp*'//1,
        wsp//1
    ]).

/** <module> DCG version of rfc5234 - ABNF (Augmented BNF)

@author Eric G Taucher
@license Simplified BSD License
*/

:- multifile element//1, portray/1.

:- working_directory(_,'C:/Users/Eric/Documents/Notes/Discourse SWI-Prolog OSU OSL/OSU OSL Prolog').

:- set_prolog_flag(double_quotes,codes).

% -----------------------------------------------------------------------------

% Augmented BNF for Syntax Specifications: ABNF - https://tools.ietf.org/pdf/rfc5234.pdf
% Errata - https://www.rfc-editor.org/errata/rfc5234

% -----------------------------------------------------------------------------

% Features borrowed from prolog_library_collection dcg by Wouter Beek
% https://github.com/wouterbeek/prolog_library_collection/blob/master/prolog/dcg.pl
% 1. Use of + and * with predicate names implementing `one or more` or `zero or more`.

% -----------------------------------------------------------------------------

% Notes:
% When copying the ABNF copy it from a text file and not a PDF as some of the characters do not translate to the correct ASCII character, e.g. ' .
% With alternation continued to another line there needs to one space at the start of the line before / .

% -----------------------------------------------------------------------------

%! rulelist(-rules(Rulelist):atom)// is det.

% ; rulelist changed per Errata
% ; Errata ID: 3076 - https://www.rfc-editor.org/errata/eid3076
% ; rulelist =  1*( rule / (*c-wsp c-nl) )
% rulelist = 1*( rule / (*WSP c-nl) )
rulelist(rules(Rulelist)) -->
    'rulelist+'(Rulelist).

'rulelist+'([Line|Rules]) -->
    line(Line),
    'rulelist*'(Rules), !.

'rulelist*'(Value) -->
    line(Line), !,
    'rulelist*'(Rules),
    {
        (
            Line == []
        ->
            Value = Rules
        ;
            Value = [Line|Rules]
        )
    }.
'rulelist*'([]) --> [].

line(Line) -->
(
    rule(Line), !
;
    (
        'wsp*'(WSP),
        cnl(CNL),
        { Line = comment_line(WSP,CNL)}
    )
).


%! 'wsp*'(-Codes:list(code))// is det.

'wsp*'([H|T]) -->
    wsp(H), !,
    'wsp*'(T).
'wsp*'([]) --> [].


%! rule(-rule(Name,Elements):atom)// is det.

% rule = rulename defined-as elements c-nl
% ; continues if next line starts
% ; with white space
rule(rule(Name,Elements)) -->
    rulename(Name),
    defined_as(_),
    elements(Elements),
    cnl(_), !.


%! rulename(-name(Name)):atom)// is det.

% rulename = ALPHA *(ALPHA / DIGIT / "-")
rulename(name(Name)) -->
    alpha(H),
    rulename_rest(T), !,
    { string_codes(Name,[H|T]) }.

rulename_rest([H|T]) -->
    (
        alpha(H), !
    ;
        digit(H), !
    ;
        "-",
        { H = 0'- }
    ), !,
    rulename_rest(T).
rulename_rest([]) --> [].


%! defined_as(-defined_as(CWSP_0,Op,CWSP_1)):atom)// is det.

% defined-as = *c-wsp ("=" / "=//") *c-wsp
% ; basic rules definition and
% ; incremental alternatives
defined_as(defined_as(CWSP_0,Op,CWSP_1)) -->
    'cwsp*'(CWSP_0),
    (
        "=",
        { Op = op('=') }, !

    ;
        ( "=", "/" ),
        { Op = op('=/') }
    ),
    'cwsp*'(CWSP_1).


%! elements(-elements(Alternation)):atom)// is det.

% ; elements changed per Errata
% ; Errata ID: 2968 - https://www.rfc-editor.org/errata/eid2968
% ; elements =  alternation *c-wsp
% elements = alternation *WSP
elements(elements(Alternation)) -->
    alternation(Alternation),
    'wsp*'(_).


%! cwsp(-Result:atom)// is det.

% c-wsp = WSP / (c-nl WSP)
cwsp(Result) -->
    wsp(WSP), !,
    { Result = wsp(WSP) }.
cwsp(Result) -->
    cnl(CNL),
    wsp(WSP),
    { Result = cwsp(cnl(CNL),wsp(WSP)) }.


%! cnl(-cnl(Value)):atom)// is det.

% c-nl = comment / CRLF
% ; comment or newline
cnl(cnl(Value)) -->
    comment(Value), !.
cnl(cnl(Value)) -->
    crlf(Value).


%! comment(-comment(Value)):atom)// is det.

% comment = ";" *(WSP / VCHAR) CRLF
comment(comment(Comment_text)) -->
    ";",
    comment_text(Comment_codes),
    { string_codes(Comment_text,Comment_codes) },
    crlf(_).

comment_text([H|T]) -->
    (
        wsp(H), !
    ;
        vchar(H)
    ), !,
    comment_text(T), !.
comment_text([]) --> [].


%! alternation(-Value:atom)// is det.

% alternation = concatenation *(*c-wsp "/" *c-wsp concatenation)
alternation(Value) -->
    concatenation(Concatenation),
    alternation_rest(Rest),
    {
        (
            Rest == []
        ->
            Value = Concatenation
        ;
            Value = alternation(Concatenation,Rest)
        )
    }.

alternation_rest(Value) -->
    'cwsp*'(_),
    "/",
    'cwsp*'(_),
    concatenation(Concatenation), !,
    alternation_rest(Rest),
    {
        (
            Rest == []
        ->
            Value = Concatenation
        ;
            Value = alternation(Concatenation,Rest)
        )
    }.
alternation_rest([]) --> [].


%! concatenation(-Value:atom)// is det.

% concatenation = repetition *(1*c-wsp repetition)
concatenation(Value) -->
    repetition(Repetition),
    concatenation_rest(Rest),
    {
        (
            Rest == []
        ->
            Value = Repetition
        ;
            Value = concatenation(Repetition,Rest)
        )
    }.

concatenation_rest(Value) -->
    'cwsp+'(_),
    repetition(Repetition), !,
    concatenation_rest(Rest),
    {
        Rest = []
    ->
        Value = Repetition
    ;
        Value = concatenation(Repetition,Rest)
    }.
concatenation_rest([]) --> [].

'cwsp+'([H|T]) -->
    (
        cnl(CNL),
        wsp(WSP), !,
        { H = cwsp(CNL,WSP) }
    ;
        cwsp(H)
    ),
    'cwsp*'(T).

'cwsp*'([H|T]) -->
    (
        cnl(CNL),
        wsp(WSP),
        { H = cwsp(CNL,WSP) }
    ;
        cwsp(H)
    ), !,
    'cwsp*'(T).
'cwsp*'([]) --> [].


%! repetition(-Value:atom)// is det.

% repetition = [repeat] element
repetition(Value) -->
    (
        repeat(Repeat), !
    ;
        { Repeat = [] }
    ),
    element(Element),
    {
        (
            Repeat = []
        ->
            Value = Element
        ;
            Value = repetition(Repeat,Element)
        )
    }.


%! repeat(-Value:atom)// is det.

% repeat = 1*DIGIT / (*DIGIT "*" *DIGIT)
% NB The order of the right hand productions is reversed from the RFP
repeat(Value) -->
    (
        (
            'digit*'(Start_codes),
            "*",
            'digit*'(End_codes),
            {
                (
                    Start_codes == []
                ->
                    Start = []
                ;
                    number_codes(Start,Start_codes)
                ),
                (
                    End_codes == []
                ->
                    End = []
                ;
                    number_codes(End,End_codes)
                ),
                repeat_functor(Start,End,Value)
            }
        )
    ), !.

repeat(exactly(Number)) -->
    'digit+'(Digit_codes),
    { number_codes(Number,Digit_codes) }.

repeat_functor([],[],zero_or_more).
repeat_functor(1,[],one_or_more).
repeat_functor(N,[],n_or_more(N)).
repeat_functor([],N,n_or_less(N)).
repeat_functor(N,N,exactly(N)).
repeat_functor(Start,End,repeat(Start,End)) :-
    (
        Start =< End
    ;
        throw(error(range('start greater than end.')))
    ).


%! 'digit+'(-Codes:list(code))// is det.

'digit+'([H|T]) -->
    digit(H),
    'digit*'(T).


%! 'digit*'(-Codes:list(code))// is det.

'digit*'([H|T]) -->
    digit(H), !,
    'digit*'(T).
'digit*'([]) --> [].


%! element(-Value:atom)// is det.

% element = rulename / group / option / char-val / num-val / prose-val
element(Rulename)  --> rulename(Rulename), !.
element(Group)     --> group(Group), !.
element(Option)    --> option(Option), !.
element(Charval)   --> charval(Charval), !.
element(Numval)    --> numval(Numval), !.
element(Prose_val) --> proseval(Prose_val).


%! group(-group(Alternation):atom)// is det.

% group = "(" *c-wsp alternation *c-wsp ")"
group(group(Alternation)) -->
    "(",
    'cwsp*'(_),
    alternation(Alternation),
    'cwsp*'(_),
    ")".


%! option(-option(Alternation):atom)// is det.

% option = "[" *c-wsp alternation *c-wsp "]"
option(option(Alternation)) -->
    "[",
    'cwsp*'(_),
    alternation(Alternation),
    'cwsp*'(_),
    "]".


%! charval(-charval(Value):atom)// is det.

% char-val = DQUOTE *(%x20-21 / %x23-7E) DQUOTE
% ; quoted string of SP and VCHAR
% ; without DQUOTE
charval(charval(Value)) -->
    dquote(Dquote),
    'charval*'(Codes),
    dquote(Dquote),
    { string_codes(Value,Codes) }, !.

'charval*'([C|T]) -->
    (
        [0x20], !,
        { C = 0x20 }
    ;
        [0x21], !,
        { C = 0x21 }
    ;
        (
            [C],
            { between(0x23,0x7E,C) }
        )
    ), !,
    'charval*'(T).
'charval*'([]) --> [].


%! numval(-numval(Value):atom)// is det.

% num-val = "%" (bin-val / dec-val / hex-val)
numval(numval(Value)) -->
    "%",
    (
        binval(Value), !
    ;
        decval(Value), !
    ;
        hexval(Value)
    ).


%! binval(-bin(Value):atom)// is det.

% bin-val = "b" 1*BIT [ 1*("." 1*BIT) / ("-" 1*BIT) ]
% ; series of concatenated bit values
% ; or single ONEOF range
binval(bin(Value)) -->
    "b",
    'bin_digit+'(Bin_codes),
    { number_bincodes(Number,Bin_codes) },
    binval_optional(Number,Value).

binval_optional(Number,sequence(Rest)) -->
    'binval_sequence+'(Number,Rest), !.
binval_optional(Start,Value) -->
    binval_range(Start,Value), !.
binval_optional(Number,value(Number)) --> [].

'binval_sequence+'(Number,[Number,H|T]) -->
    binval_sequence_number(H),
    'binval_sequence*'(T).

'binval_sequence*'([H|T]) -->
    binval_sequence_number(H), !,
    'binval_sequence*'(T).
'binval_sequence*'([]) --> [].

binval_sequence_number(Number) -->
    ".",
    'bin_digit+'(Bin_codes),
    { number_bincodes(Number,Bin_codes) }.

binval_range(Start,range(Start,End)) -->
    "-",
    'bin_digit+'(Bin_codes),
    { number_bincodes(End,Bin_codes) }.

number_bincodes(Dec_number,Bin_codes) :-
    atom_to_term([0'0,0'b|Bin_codes],Dec_number,_).



%! 'bin_digit+'(-Codes:list(code))// is det.

'bin_digit+'([H|T]) -->
    bit(H),
    'bin_digit*'(T).


%! 'bin_digit*'(-Codes:list(code))// is det.

'bin_digit*'([H|T]) -->
    bit(H), !,
    'bin_digit*'(T).
'bin_digit*'([]) --> [].


%! decval(-dec(Value):atom)// is det.

% dec-val = "d" 1*DIGIT [ 1*("." 1*DIGIT) / ("-" 1*DIGIT) ]
decval(dec(Value)) -->
    "d",
    'digit+'(Dec_codes),
    { number_codes(Number,Dec_codes) },
    decval_optional(Number,Value).

decval_optional(Number,sequence(Rest)) -->
    'decval_sequence+'(Number,Rest), !.
decval_optional(Start,Value) -->
    decval_range(Start,Value), !.
decval_optional(Number,value(Number)) --> [].

'decval_sequence+'(Number,[Number,H|T]) -->
    decval_sequence_number(H),
    'decval_sequence*'(T).

'decval_sequence*'([H|T]) -->
    decval_sequence_number(H), !,
    'decval_sequence*'(T).
'decval_sequence*'([]) --> [].

decval_sequence_number(Number) -->
    ".",
    'digit+'(Dec_codes),
    { number_codes(Number,Dec_codes) }.

decval_range(Start,range(Start,End)) -->
    "-",
    'digit+'(Dec_codes),
    { number_codes(End,Dec_codes) }.



%! hexval(-hex(Value):atom)// is det.

% hex-val = "x" 1*HEXDIG [ 1*("." 1*HEXDIG) / ("-" 1*HEXDIG) ]
hexval(hex(Value)) -->
    "x",
    'hex_digit+'(Hex_codes),
    { number_hexcodes(Number,Hex_codes) },
    hexval_optional(Number,Value).

hexval_optional(Number,sequence(Rest)) -->
    'hexval_sequence+'(Number,Rest), !.
hexval_optional(Start,Value) -->
    hexval_range(Start,Value), !.
hexval_optional(Number,value(Number)) --> [].

'hexval_sequence+'(Number,[Number,H|T]) -->
    hexval_sequence_number(H),
    'hexval_sequence*'(T).

'hexval_sequence*'([H|T]) -->
    hexval_sequence_number(H), !,
    'hexval_sequence*'(T).
'hexval_sequence*'([]) --> [].

hexval_sequence_number(Number) -->
    ".",
    'hex_digit+'(Hex_codes),
    { number_hexcodes(Number,Hex_codes) }.

hexval_range(Start,range(Start,End)) -->
    "-",
    'hex_digit+'(Hex_codes),
    { number_hexcodes(End,Hex_codes) }.

number_hexcodes(Dec_number,Hex_codes) :-
    atom_to_term([0'0,0'x|Hex_codes],Dec_number,_).


%! 'hex_digit+'(-Codes:list(code))// is det.

'hex_digit+'([H|T]) -->
    hexdig(H),
    'hex_digit*'(T).


%! 'hex_digit*'(-Codes:list(code))// is det.

'hex_digit*'([H|T]) -->
    hexdig(H), !,
    'hex_digit*'(T).
'hex_digit*'([]) --> [].


%! proseval(-prose(Value):string)// is det.

% prose-val = "<" *(%x20-3D / %x3F-7E) ">"
% ; bracketed string of SP and VCHAR
% ; without angles
% ; prose description, to be used as
% ; last resort
proseval(prose(Value)) -->
    "<",
    proseval_text(Codes),
    ">", !,
    { string_codes(Value,Codes) }.

proseval_text([H|T]) -->
    [H],
    (
        { between(0x20,0x3D,H) }, !
    ;
        { between(0x3F,0x7E,H) }
    ), !,
    proseval_text(T).
proseval_text([]) --> [].


%! alpha(?Code:code)// is det.

% ALPHA = %x41-5A / %x61-7A ; A-Z / a-z
alpha(C) -->
    [C],
    (
        { between(0x41,0x5A,C) }
    ;
        { between(0x61,0x7A,C) }
    ).


%! bit(-Code:code)// is det.

% BIT = "0" / "1"
bit(0'0) --> "0", !.
bit(0'1) --> "1".


%! char(-Code:code)// is det.

% CHAR = %x01-7F
% ; any 7-bit US-ASCII character,
% ; excluding NUL
char(C) -->
    [C],
    { between(0x01,0x7F,C) }.


%! cr(-Code:code)// is det.

% CR = %x0D
cr(0x0D) -->[0x0D].


%! crlf(-crlf(CR,LF):atom)// is det.

% ; carriage return
% CRLF = CR LF
% ; Internet standard newline
crlf(crlf(CR,LF)) -->
    cr(CR),
    lf(LF).


%! ctl(-ctl(C):atom)// is det.

% CTL = %x00-1F / %x7F
% ; controls
ctl(C) -->
    [C],
    { between(0x00,0x1F,C) }.


%! digit(-Codes:list(code))// is det.

% DIGIT = %x30-39
% ; 0-9
digit(D) -->
    [D],
    { between(0'0,0'9,D) }.


%! dquote(-Code:code)// is det.

% DQUOTE = %x22
% ; " (Double Quote)
dquote(0'") --> [0x22].


%! hexdig(-Codes:list(code))// is det.

% HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
hexdig(D) -->
        digit(D), !
    ;
        (
            [D],
            { between(0'A,0'F,D) }
        ).


%! htab(-Code:code)// is det.

% HTAB = %x09
% ; horizontal tab
htab(0x09) --> [0x09].


%! lf(-Code:code)// is det.

% LF = %x0A
% ; linefeed
lf(0x0A) --> [0x0A].


%! lwsp(-Codes:list(code))// is det.

% LWSP = *(WSP / CRLF WSP)
% ; Use of this linear-white-space rule
% ; permits lines containing only white
% ; space that are no longer legal in
% ; mail headers and have caused
% ; interoperability problems in other
% ; contexts.
% ; Do not use when defining mail
% ; headers and use with caution in
% ; other contexts.
lwsp([H|T]) -->
    (
        wsp(WSP), !,
        { H = wsp(WSP) }
    )
    ;
    (
        crlf(CRLF),wsp(WSP),
        { H = group(crlf(CRLF),wsp(WSP)) }
    ), !,
    lwsp(T).
lwsp([]) --> [].


%! octet(-Code:code)// is det.

% OCTET = %x00-FF
% ; 8 bits of data
octet(O) -->
    [O],
    { between(0x00,0xFF,O) }.


%! sp(-Code:code)// is det.

% SP = %x20
sp(0x20) -->
    [0x20].


%! vchar(-Code:code)// is det.

% VCHAR = %x21-7E
% ; visible (printing) characters
vchar(C) -->
    [C],
    { between(0x21,0x7E,C) }.


%! wsp(-Code:code)// is det.

% WSP = SP / HTAB
% ; white space
wsp(Result) -->
    (
        sp(Result), !
    ;
        htab(Result)
    ).

% -----------------------------------------------------------------------------

%! portray(-Value):atom)// is det.

portray(rules(List)) :-
    portray(List).

portray([H|T]) :-
    portray(H),
    portray(T).
portray([]).

portray(comment_line(_,_)).

portray(rule(name(Name),elements(Elements))) :-
    portray(name(Name)),
    write(' = '),
    portray(Elements),
    write('\r\n').

portray(name(Name)) :-
    write(Name).

portray(alternation(First,Second)) :-
    portray(implied_group(First)),
    write(' / '),
    portray(implied_group(Second)).

portray(implied_group(Item)) :-
    (
        Item = concatenation(_,_)
    ->
        (
            write('( '),
            portray(Item),
            write(' )')
        )
    ;
        portray(Item)
    ).

portray(concatenation(First,Second)) :-
    portray(First),
    write(' '),
    portray(Second).

portray(repetition(exactly(N),Element)) :-
    write(N),
    portray(Element).

portray(repetition(zero_or_more,Element)) :-
    write('*'),
    portray(Element).

portray(repetition(one_or_more,Element)) :-
    write('1*'),
    portray(Element).

portray(repetition(n_or_more(N),Element)) :-
    write(N),
    write('*'),
    portray(Element).

portray(repetition(n_or_less(N),Element)) :-
    write('*'),
    write(N),
    portray(Element).

portray(repetition(repeat(Start,End),Element)) :-
    write(Start),
    write('*'),
    write(End),
    portray(Element).

portray(charval(Char)) :-
    write('"'),
    write(Char),
    write('"').

portray(group(Element)) :-
    write('( '),
    portray(Element),
    write(' )').

portray(option(Element)) :-
    write('[ '),
    portray(Element),
    write(' ]').

portray(numval(bin(sequence([H|T])))) :-
    write('%b'),
    portray(bin(value(H))),
    portray(bin(sequence(T))).

portray(bin(sequence([H|T]))) :-
    write('.'),
    portray(bin(value(H))),
    portray(bin(sequence(T))).
portray(bin(sequence([]))).

portray(numval(bin(range(Start_decimal,End_decimal)))) :-
    write('%b'),
    portray(bin(value(Start_decimal))),
    write('-'),
    portray(bin(value(End_decimal))).

portray(numval(bin(value(Value_dec)))) :-
    write('%b'),
    portray(bin(value(Value_dec))).

portray(bin(value(Value_dec))) :-
    dec_to_bin(Value_dec,Value_bin),
    write(Value_bin).

portray(numval(dec(sequence([H|T])))) :-
    write('%d'),
    portray(dec(value(H))),
    portray(dec(sequence(T))).

portray(dec(sequence([H|T]))) :-
    write('.'),
    portray(dec(value(H))),
    portray(dec(sequence(T))).
portray(dec(sequence([]))).

portray(numval(dec(range(Start_decimal,End_decimal)))) :-
    write('%d'),
    portray(dec(value(Start_decimal))),
    write('-'),
    portray(dec(value(End_decimal))).

portray(numval(dec(value(Value_dec)))) :-
    write('%d'),
    portray(dec(value(Value_dec))).

portray(dec(value(Value_dec))) :-
    write(Value_dec).

portray(numval(hex(sequence([H|T])))) :-
    write('%x'),
    portray(hex(value(H))),
    portray(hex(sequence(T))).

portray(hex(sequence([H|T]))) :-
    write('.'),
    portray(hex(value(H))),
    portray(hex(sequence(T))).
portray(hex(sequence([]))).

portray(numval(hex(range(Start_decimal,End_decimal)))) :-
    write('%x'),
    portray(hex(value(Start_decimal))),
    write('-'),
    portray(hex(value(End_decimal))).

portray(numval(hex(value(Value_dec)))) :-
    write('%x'),
    portray(hex(value(Value_dec))).

portray(hex(value(Value_dec))) :-
    dec_to_hex(Value_dec,Value_hex),
    write(Value_hex).

portray(prose(Text)) :-
    write('<'),
    write(Text),
    write('>').

dec_to_hex(Value,Atom) :-
    hex_canonical_width(Value,Width),
    format(atom(Atom),'~|~`0t~16R~*|',[Value,Width]), !.
dec_to_hex(Value,Atom) :-
    format(atom(Atom),'~16R',Value).

hex_canonical_width(Value,2) :- Value =< 0xFF, !.
hex_canonical_width(Value,4) :- Value =< 0xFFFF, !.
hex_canonical_width(Value,8) :- Value =< 0xFFFFFFFF, !.
hex_canonical_width(Value,16) :- Value =< 0xFFFFFFFFFFFFFFFF.

dec_to_bin(Value,Atom) :-
    bin_canonical_width(Value,Width),
    format(atom(Atom),'~|~`0t~2r~*|',[Value,Width]), !.
dec_to_bin(Value,Atom) :-
    format(atom(Atom),'~2r',Value).

bin_canonical_width(Value,4) :- Value =< 0b1111, !.
bin_canonical_width(Value,8) :- Value =< 0b11111111, !.
bin_canonical_width(Value,16) :- Value =< 0b1111111111111111.

% -----------------------------------------------------------------------------

recognize(Abnf_path) :-
    parse(Abnf_path,_).

% ?- recognize('rfc3986.abnf').
% ?- recognize('rfc5234.abnf').
% ?- recognize('rfc7230.abnf').

parse(Abnf_path,Rules) :-
    setup_call_cleanup(
        open(Abnf_path,read,Abnf_stream),
        (
            set_stream(Abnf_stream, newline(posix)),
            read_stream_to_codes(Abnf_stream,Codes),
            DCG = rulelist(Rules),
            phrase(DCG,Codes,[])
        ),
        close(Abnf_stream)
    ).

% ?- parse('rfc3986.abnf',Term).
% ?- parse('rfc5234.abnf',Term).
% ?- parse('rfc7230.abnf',Term).

round_trip(Abnf_path) :-
    setup_call_cleanup(
        open(Abnf_path,read,Abnf_stream),
        (
            set_stream(Abnf_stream, newline(posix)),
            read_stream_to_codes(Abnf_stream,Codes),
            DCG = rulelist(Rules),
            phrase(DCG,Codes,[])
        ),
        close(Abnf_stream)
    ),
    setup_call_cleanup(
        open('portray.txt',write,S,[]),
        with_output_to(S, portray(Rules)),
        close(S)
    ).

% ?- rfc5234:round_trip('rfc3986.abnf').
% ?- rfc5234:round_trip('rfc5234.abnf').
% ?- rfc5234:round_trip('rfc7230.abnf').

fixed_point_check(Abnf_path) :-
    setup_call_cleanup(
        open(Abnf_path,read,Abnf_stream),
        (
            set_stream(Abnf_stream, newline(posix)),
            read_stream_to_codes(Abnf_stream,Codes_1),
            DCG1 = rulelist(Rules_1),
            phrase(DCG1,Codes_1,[])
        ),
        close(Abnf_stream)
    ),
    with_output_to(string(BNF_1),portray(Rules_1)),
    string_codes(BNF_1,Codes2),
    DCG2 = rulelist(Rules_2),
    phrase(DCG2,Codes2,[]),
    with_output_to(string(BNF_2),portray(Rules_2)),
    assertion( BNF_1 == BNF_2).

% ?- fixed_point_check('rfc3986.abnf').
% ?- fixed_point_check('rfc5234.abnf').
% ?- fixed_point_check('rfc7230.abnf').

% -----------------------------------------------------------------------------

:- begin_tests(abnf).

rule_test( success, "sub-delims = \"!\" / \"$\" / \"&\" / \"'\" / \"(\" / \")\"\r\n  / \"*\" / \"+\" / \",\" / \";\" / \"=\"\r\n"                                             , rule(name("sub-delims"),elements(alternation(charval("!"),alternation(charval("$"),alternation(charval("&"),alternation(charval("'"),alternation(charval("("),alternation(charval(")"),alternation(charval("*"),alternation(charval("+"),alternation(charval(","),alternation(charval(";"),charval("=")))))))))))))                                                   , "sub-delims = \"!\" / \"$\" / \"&\" / \"'\" / \"(\" / \")\" / \"*\" / \"+\" / \",\" / \";\" / \"=\"\r\n" ).
rule_test( success, "defined-as = *c-wsp (\"=\" / \"=/\") *c-wsp\r\n"                                                                                                         , rule(name("defined-as"),elements(concatenation(repetition(zero_or_more,name("c-wsp")),concatenation(group(alternation(charval("="),charval("=/"))),repetition(zero_or_more,name("c-wsp"))))))                                                                                                                                                                         , "defined-as = *c-wsp ( \"=\" / \"=/\" ) *c-wsp\r\n" ).
rule_test( success, "rule = a\r\n / b\r\n"                                                                                                                                    , rule(name("rule"),elements(alternation(name("a"),name("b"))))                                                                                                                                                                                                                                                                                                         , "rule = a / b\r\n" ).
rule_test( success, "BWS = OWS\r\n"                                                                                                                                           , rule(name("BWS"),elements(name("OWS")))                                                                                                                                                                                                                                                                                                                               , "BWS = OWS\r\n" ).
rule_test( success, "Connection = *( \",\" OWS ) connection-option *( OWS \",\" [ OWS connection-option ] )\r\n"                                                              , rule(name("Connection"),elements(concatenation(repetition(zero_or_more,group(concatenation(charval(","),name("OWS")))),concatenation(name("connection-option"),repetition(zero_or_more,group(concatenation(name("OWS"),concatenation(charval(","),option(concatenation(name("OWS"),name("connection-option")))))))))))                                                , "Connection = *( \",\" OWS ) connection-option *( OWS \",\" [ OWS connection-option ] )\r\n" ).
rule_test( success, "Content-Length = 1*DIGIT\r\n"                                                                                                                            , rule(name("Content-Length"),elements(repetition(one_or_more,name("DIGIT"))))                                                                                                                                                                                                                                                                                          , "Content-Length = 1*DIGIT\r\n" ).
rule_test( success, "HTTP-message = start-line *( header-field CRLF ) CRLF [ message-body ]\r\n"                                                                              , rule(name("HTTP-message"),elements(concatenation(name("start-line"),concatenation(repetition(zero_or_more,group(concatenation(name("header-field"),name("CRLF")))),concatenation(name("CRLF"),option(name("message-body")))))))                                                                                                                                       , "HTTP-message = start-line *( header-field CRLF ) CRLF [ message-body ]\r\n" ).
rule_test( success, "dec-octet = DIGIT ; 0-9\r\n / %x31-39 DIGIT ; 10-99\r\n / \"1\" 2DIGIT ; 100-199\r\n / \"2\" %x30-34 DIGIT ; 200-249\r\n / \"25\" %x30-35 ; 250-255\r\n" , rule(name("dec-octet"),elements(alternation(name("DIGIT"),alternation(concatenation(numval(hex(range(49,57))),name("DIGIT")),alternation(concatenation(charval("1"),repetition(exactly(2),name("DIGIT"))),alternation(concatenation(charval("2"),concatenation(numval(hex(range(48,52))),name("DIGIT"))),concatenation(charval("25"),numval(hex(range(48,53)))))))))) , "dec-octet = DIGIT / ( %x31-39 DIGIT ) / ( \"1\" 2DIGIT ) / ( \"2\" %x30-34 DIGIT ) / ( \"25\" %x30-35 )\r\n" ).
rule_test( success, "CR = %x0D\r\n"                                                                                                                                           , rule(name("CR"),elements(numval(hex(value(13)))))                                                                                                                                                                                                                                                                                                                     , "CR = %x0D\r\n" ).
rule_test( success, "h16 = 1*4HEXDIG\r\n"                                                                                                                                     , rule(name("h16"),elements(repetition(repeat(1,4),name("HEXDIG"))))                                                                                                                                                                                                                                                                                                    , "h16 = 1*4HEXDIG\r\n" ).
rule_test( success, "IPvFuture = \"v\" 1HEXDIG \".\" 1*(unreserved / sub-delims / \":\")\r\n"                                                                                 , rule(name("IPvFuture"),elements(concatenation(charval("v"),concatenation(repetition(exactly(1),name("HEXDIG")),concatenation(charval("."),repetition(one_or_more,group(alternation(name("unreserved"),alternation(name("sub-delims"),charval(":"))))))))))                                                                                                            , "IPvFuture = \"v\" 1HEXDIG \".\" 1*( unreserved / sub-delims / \":\" )\r\n" ).
rule_test( success, "ls32 = (h16 \":\" h16) / IPv4address\r\n"                                                                                                                , rule(name("ls32"),elements(alternation(group(concatenation(name("h16"),concatenation(charval(":"),name("h16")))),name("IPv4address"))))                                                                                                                                                                                                                               , "ls32 = ( h16 \":\" h16 ) / IPv4address\r\n" ).
rule_test( success, "repeat = 1*DIGIT / (*DIGIT \"*\" *DIGIT)\r\n"                                                                                                            , rule(name("repeat"),elements(alternation(repetition(one_or_more,name("DIGIT")),group(concatenation(repetition(zero_or_more,name("DIGIT")),concatenation(charval("*"),repetition(zero_or_more,name("DIGIT"))))))))                                                                                                                                                     , "repeat = 1*DIGIT / ( *DIGIT \"*\" *DIGIT )\r\n" ).
rule_test( success, "char-val = DQUOTE *( %x20-21 / %x23-7E) DQUOTE\r\n"                                                                                                      , rule(name("char-val"),elements(concatenation(name("DQUOTE"),concatenation(repetition(zero_or_more,group(alternation(numval(hex(range(32,33))),numval(hex(range(35,126)))))),name("DQUOTE")))))                                                                                                                                                                        , "char-val = DQUOTE *( %x20-21 / %x23-7E ) DQUOTE\r\n" ).
rule_test( success, "HTTP-name = %x48.54.54.50\r\n"                                                                                                                           , rule(name("HTTP-name"),elements(numval(hex(sequence([0'H,0'T,0'T,0'P]))))) ).

rule_test(    fail,                    "" ).  % Must have one rule
rule_test(    fail, "r\s=\sa\r\n/\sb\r\n" ).  % Must have one space before / for alternate on new line.

test(rule_success,[forall(rule_test(success,Input,Expected_result,Expected_portray))]) :-
    DCG = rule(Rule),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]),
    with_output_to(string(Portray),portray(Rule)),

    assertion( Rule == Expected_result ),
    assertion( Portray == Expected_portray ).

test(rule_fail,[fail,forall(rule_test(fail,Input))]) :-
    DCG = rule(_),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]).

comment_test( success, "; '!'-'''\r\n", comment(" '!'-'''") ).
comment_test(    fail, "").

test(comment_success,[forall(comment_test(success,Input,Expected_result))]) :-
    DCG = comment(Comment),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]),

    assertion( Comment == Expected_result ).

test(comment_fail,[fail,forall(comment_test(fail,Input))]) :-
    DCG = comment(_),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]).

cr_test( success, "\x0D", 0x0D ).
cr_test(    fail, "\x00").
cr_test(    fail, "\x0C").
cr_test(    fail, "\x0E").
cr_test(    fail, "\x7F").
cr_test(    fail, "\xFF").

test(cr_success,[forall(cr_test(success,Input,Expected_result))]) :-
    DCG = cr(CR),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]),

    assertion( CR == Expected_result ).

test(cr_fail,[fail,forall(cr_test(fail,Input))]) :-
    DCG = cr(_),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]).

rulename_test( success,   "a", name("a")   ).
rulename_test( success,  "ab", name("ab")  ).
rulename_test( success,  "a1", name("a1")  ).
rulename_test( success,  "a-", name("a-")  ).
rulename_test( success, "abc", name("abc") ).
rulename_test( success, "a1b", name("a1b") ).
rulename_test( success, "a-b", name("a-b") ).
rulename_test(    fail, "-").
rulename_test(    fail, "(").
rulename_test(    fail, "[").
rulename_test(    fail, "\"").
rulename_test(    fail, "%").
rulename_test(    fail, "\x00").
rulename_test(    fail, "\x0C").
rulename_test(    fail, "\x0E").
rulename_test(    fail, "\x7F").
rulename_test(    fail, "\xFF").

test(rulename_success,[forall(rulename_test(success,Input,Expected_result))]) :-
    DCG = rulename(Rulename),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]),

    assertion( Rulename == Expected_result ).

test(rulename_fail,[fail,forall(rulename_test(fail,Input))]) :-
    DCG = rulename(_),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]).

decval_range_rest_test( success,   "-0", 1,  range(1,0) ).
decval_range_rest_test( success,   "-9", 1,  range(1,9) ).
decval_range_rest_test( success,  "-00", 1,  range(1,0) ).
decval_range_rest_test( success,  "-09", 1,  range(1,9) ).
decval_range_rest_test( success,  "-90", 1, range(1,90) ).
decval_range_rest_test( success,  "-99", 1, range(1,99) ).
decval_range_rest_test(    fail,     "").
decval_range_rest_test(    fail,    "-").
decval_range_rest_test(    fail,    "a").
decval_range_rest_test(    fail,    "f").
decval_range_rest_test(    fail,   "-A").
decval_range_rest_test(    fail,   "-F").
decval_range_rest_test(    fail,  "-0A").
decval_range_rest_test(    fail,  "-0F").
decval_range_rest_test(    fail,  "-9A").
decval_range_rest_test(    fail,  "-9F").
decval_range_rest_test(    fail,  "-A0").
decval_range_rest_test(    fail,  "-A9").
decval_range_rest_test(    fail,  "-AA").
decval_range_rest_test(    fail,  "-AF").
decval_range_rest_test(    fail,  "-F0").
decval_range_rest_test(    fail,  "-F9").
decval_range_rest_test(    fail,  "-FA").
decval_range_rest_test(    fail,  "-FF").
decval_range_rest_test(    fail,    "(").
decval_range_rest_test(    fail,    "[").
decval_range_rest_test(    fail,   "\"").
decval_range_rest_test(    fail,    "%").
decval_range_rest_test(    fail,   "--").
decval_range_rest_test(    fail, "-A-B").
decval_range_rest_test(    fail, "\x00").
decval_range_rest_test(    fail, "\x0C").
decval_range_rest_test(    fail, "\x0E").
decval_range_rest_test(    fail, "\x7F").
decval_range_rest_test(    fail, "\xFF").

test(decval_range_rest_success,[forall(decval_range_rest_test(success,Input,Start,Expected_result))]) :-
    DCG = decval_range(Start,Result),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]),

    assertion( Result == Expected_result ).

test(decval_range_rest_fail,[fail,forall(decval_range_rest_test(fail,Input))]) :-
    DCG = decval_range(_,_),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]).

'decval_sequence+_test'( success,   ".0", 1, [1, 0] ).
'decval_sequence+_test'( success,   ".9", 1, [1, 9] ).
'decval_sequence+_test'( success,  ".00", 1, [1, 0] ).
'decval_sequence+_test'( success,  ".09", 1, [1, 9] ).
'decval_sequence+_test'( success,  ".90", 1, [1,90] ).
'decval_sequence+_test'( success,  ".99", 1, [1,99] ).
'decval_sequence+_test'(    fail,     "").
'decval_sequence+_test'(    fail,    "-").
'decval_sequence+_test'(    fail,    "a").
'decval_sequence+_test'(    fail,    "f").
'decval_sequence+_test'(    fail,   ".A").
'decval_sequence+_test'(    fail,   ".F").
'decval_sequence+_test'(    fail,  ".0A").
'decval_sequence+_test'(    fail,  ".0F").
'decval_sequence+_test'(    fail,  ".9A").
'decval_sequence+_test'(    fail,  ".9F").
'decval_sequence+_test'(    fail,  ".A0").
'decval_sequence+_test'(    fail,  ".A9").
'decval_sequence+_test'(    fail,  ".AA").
'decval_sequence+_test'(    fail,  ".AF").
'decval_sequence+_test'(    fail,  ".F0").
'decval_sequence+_test'(    fail,  ".F9").
'decval_sequence+_test'(    fail,  ".FA").
'decval_sequence+_test'(    fail,  ".FF").
'decval_sequence+_test'(    fail,    "(").
'decval_sequence+_test'(    fail,    "[").
'decval_sequence+_test'(    fail,   "\"").
'decval_sequence+_test'(    fail,    "%").
'decval_sequence+_test'(    fail,   "--").
'decval_sequence+_test'(    fail, "-A-B").
'decval_sequence+_test'(    fail, "\x00").
'decval_sequence+_test'(    fail, "\x0C").
'decval_sequence+_test'(    fail, "\x0E").
'decval_sequence+_test'(    fail, "\x7F").
'decval_sequence+_test'(    fail, "\xFF").

test('decval_sequence+_success',[forall('decval_sequence+_test'(success,Input,Number,Expected_result))]) :-
    DCG = 'decval_sequence+'(Number,Result),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]),

    assertion( Result == Expected_result ).

test('decval_sequence+_fail',[fail,forall('decval_sequence+_test'(fail,Input))]) :-
    DCG = 'decval_sequence+'(_,_),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]).

'hexval_sequence+_test'( success,      ".0", 1,     [1,  0] ).
'hexval_sequence+_test'( success,      ".9", 1,     [1,  9] ).
'hexval_sequence+_test'( success,      ".A", 1,     [1, 10] ).
'hexval_sequence+_test'( success,      ".F", 1,     [1, 15] ).
'hexval_sequence+_test'( success,     ".00", 1,     [1,  0] ).
'hexval_sequence+_test'( success,     ".09", 1,     [1,  9] ).
'hexval_sequence+_test'( success,     ".0A", 1,     [1, 10] ).
'hexval_sequence+_test'( success,     ".0F", 1,     [1, 15] ).
'hexval_sequence+_test'( success,     ".90", 1,     [1,144] ).
'hexval_sequence+_test'( success,     ".99", 1,     [1,153] ).
'hexval_sequence+_test'( success,     ".9A", 1,     [1,154] ).
'hexval_sequence+_test'( success,     ".9F", 1,     [1,159] ).
'hexval_sequence+_test'( success,     ".A0", 1,     [1,160] ).
'hexval_sequence+_test'( success,     ".A9", 1,     [1,169] ).
'hexval_sequence+_test'( success,     ".AA", 1,     [1,170] ).
'hexval_sequence+_test'( success,     ".AF", 1,     [1,175] ).
'hexval_sequence+_test'( success,     ".F0", 1,     [1,240] ).
'hexval_sequence+_test'( success,     ".F9", 1,     [1,249] ).
'hexval_sequence+_test'( success,     ".FA", 1,     [1,250] ).
'hexval_sequence+_test'( success,     ".FF", 1,     [1,255] ).
'hexval_sequence+_test'( success,  ".FF.FF", 1, [1,255,255] ).
'hexval_sequence+_test'(    fail,     "").
'hexval_sequence+_test'(    fail,    "-").
'hexval_sequence+_test'(    fail,    "a").
'hexval_sequence+_test'(    fail,    "f").
'hexval_sequence+_test'(    fail,    "(").
'hexval_sequence+_test'(    fail,    "[").
'hexval_sequence+_test'(    fail,   "\"").
'hexval_sequence+_test'(    fail,    "%").
'hexval_sequence+_test'(    fail,   "--").
'hexval_sequence+_test'(    fail, "-A-B").
'hexval_sequence+_test'(    fail, "\x00").
'hexval_sequence+_test'(    fail, "\x0C").
'hexval_sequence+_test'(    fail, "\x0E").
'hexval_sequence+_test'(    fail, "\x7F").
'hexval_sequence+_test'(    fail, "\xFF").

test('hexval_sequence+_success',[forall('hexval_sequence+_test'(success,Input,Number,Expected_result))]) :-
    DCG = 'hexval_sequence+'(Number,Result),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]),

    assertion( Result == Expected_result ).

test('hexval_sequence+_fail',[fail,forall('hexval_sequence+_test'(fail,Input))]) :-
    DCG = 'hexval_sequence+'(0,_),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]).

number_hexcodes_test( success,   "0",   0 ).
number_hexcodes_test( success,   "9",   9 ).
number_hexcodes_test( success,   "A",  10 ).
number_hexcodes_test( success,   "F",  15 ).
number_hexcodes_test( success,   "a",  10 ).
number_hexcodes_test( success,   "f",  15 ).
number_hexcodes_test( success,  "00",   0 ).
number_hexcodes_test( success,  "09",   9 ).
number_hexcodes_test( success,  "0A",  10 ).
number_hexcodes_test( success,  "0F",  15 ).
number_hexcodes_test( success,  "90", 144 ).
number_hexcodes_test( success,  "99", 153 ).
number_hexcodes_test( success,  "9A", 154 ).
number_hexcodes_test( success,  "9F", 159 ).
number_hexcodes_test( success,  "A0", 160 ).
number_hexcodes_test( success,  "A9", 169 ).
number_hexcodes_test( success,  "AA", 170 ).
number_hexcodes_test( success,  "AF", 175 ).
number_hexcodes_test( success,  "F0", 240 ).
number_hexcodes_test( success,  "F9", 249 ).
number_hexcodes_test( success,  "FA", 250 ).
number_hexcodes_test( success,  "FF", 255 ).
number_hexcodes_test(  error1,     "").
number_hexcodes_test(  error1,    "-").
number_hexcodes_test(  error1,    "(").
number_hexcodes_test(  error1,    "[").
number_hexcodes_test(  error1,    "%").
number_hexcodes_test(  error1,   "--").
number_hexcodes_test(  error1, "-A-B").
number_hexcodes_test(  error1, "\x00").
number_hexcodes_test(  error1, "\x0C").
number_hexcodes_test(  error1, "\x0E").
number_hexcodes_test(  error1, "\x7F").
number_hexcodes_test(  error1, "\xFF").
number_hexcodes_test(  error2,   "\"").

test(number_hexcodes_success,[forall(number_hexcodes_test(success,Input,Expected_result))]) :-
    string_codes(Input,Codes),
    number_hexcodes(Result,Codes),

    assertion( Result == Expected_result ).

test(number_hexcodes_fail,[error(syntax_error(illegal_number),_),forall(number_hexcodes_test(error1,Input))]) :-
    string_codes(Input,Codes),
    number_hexcodes(_,Codes).

test(number_hexcodes_fail,[error(syntax_error(end_of_file_in_quoted(_)),_),forall(number_hexcodes_test(error2,Input))]) :-
    string_codes(Input,Codes),
    number_hexcodes(_,Codes).

hexval_range_rest_test( success,   "-0", 1,   range(1,0) ).
hexval_range_rest_test( success,   "-9", 1,   range(1,9) ).
hexval_range_rest_test( success,   "-A", 1,  range(1,10) ).
hexval_range_rest_test( success,   "-F", 1,  range(1,15) ).
hexval_range_rest_test( success,  "-00", 1,   range(1,0) ).
hexval_range_rest_test( success,  "-09", 1,   range(1,9) ).
hexval_range_rest_test( success,  "-0A", 1,  range(1,10) ).
hexval_range_rest_test( success,  "-0F", 1,  range(1,15) ).
hexval_range_rest_test( success,  "-90", 1, range(1,144) ).
hexval_range_rest_test( success,  "-99", 1, range(1,153) ).
hexval_range_rest_test( success,  "-9A", 1, range(1,154) ).
hexval_range_rest_test( success,  "-9F", 1, range(1,159) ).
hexval_range_rest_test( success,  "-A0", 1, range(1,160) ).
hexval_range_rest_test( success,  "-A9", 1, range(1,169) ).
hexval_range_rest_test( success,  "-AA", 1, range(1,170) ).
hexval_range_rest_test( success,  "-AF", 1, range(1,175) ).
hexval_range_rest_test( success,  "-F0", 1, range(1,240) ).
hexval_range_rest_test( success,  "-F9", 1, range(1,249) ).
hexval_range_rest_test( success,  "-FA", 1, range(1,250) ).
hexval_range_rest_test( success,  "-FF", 1, range(1,255) ).
hexval_range_rest_test(    fail,     "").
hexval_range_rest_test(    fail,    "-").
hexval_range_rest_test(    fail,    "a").
hexval_range_rest_test(    fail,    "f").
hexval_range_rest_test(    fail,    "(").
hexval_range_rest_test(    fail,    "[").
hexval_range_rest_test(    fail,   "\"").
hexval_range_rest_test(    fail,    "%").
hexval_range_rest_test(    fail,   "--").
hexval_range_rest_test(    fail, "-A-B").
hexval_range_rest_test(    fail, "\x00").
hexval_range_rest_test(    fail, "\x0C").
hexval_range_rest_test(    fail, "\x0E").
hexval_range_rest_test(    fail, "\x7F").
hexval_range_rest_test(    fail, "\xFF").

test(hexval_range_rest_success,[forall(hexval_range_rest_test(success,Input,Number,Expected_result))]) :-
    DCG = hexval_range(Number,Result),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]),

    assertion( Result == Expected_result ).

test(hexval_range_rest_fail,[fail,forall(hexval_range_rest_test(fail,Input))]) :-
    DCG = hexval_range(0,_),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]).

'hexdig*_test'( success,    "",        [] ).
'hexdig*_test'( success,   "0",     [0'0] ).
'hexdig*_test'( success,   "9",     [0'9] ).
'hexdig*_test'( success,   "A",     [0'A] ).
'hexdig*_test'( success,   "F",     [0'F] ).
'hexdig*_test'( success,  "00", [0'0,0'0] ).
'hexdig*_test'( success,  "09", [0'0,0'9] ).
'hexdig*_test'( success,  "0A", [0'0,0'A] ).
'hexdig*_test'( success,  "0F", [0'0,0'F] ).
'hexdig*_test'( success,  "90", [0'9,0'0] ).
'hexdig*_test'( success,  "99", [0'9,0'9] ).
'hexdig*_test'( success,  "9A", [0'9,0'A] ).
'hexdig*_test'( success,  "9F", [0'9,0'F] ).
'hexdig*_test'( success,  "A0", [0'A,0'0] ).
'hexdig*_test'( success,  "A9", [0'A,0'9] ).
'hexdig*_test'( success,  "AA", [0'A,0'A] ).
'hexdig*_test'( success,  "AF", [0'A,0'F] ).
'hexdig*_test'( success,  "FF", [0'F,0'F] ).
'hexdig*_test'( success,  "F0", [0'F,0'0] ).
'hexdig*_test'( success,  "F9", [0'F,0'9] ).
'hexdig*_test'( success,  "FA", [0'F,0'A] ).
'hexdig*_test'( success,  "FF", [0'F,0'F] ).
'hexdig*_test'(    fail,    "-").
'hexdig*_test'(    fail,    "a").
'hexdig*_test'(    fail,    "f").
'hexdig*_test'(    fail,    "(").
'hexdig*_test'(    fail,    "[").
'hexdig*_test'(    fail,   "\"").
'hexdig*_test'(    fail,    "%").
'hexdig*_test'(    fail, "\x00").
'hexdig*_test'(    fail, "\x0C").
'hexdig*_test'(    fail, "\x0E").
'hexdig*_test'(    fail, "\x7F").
'hexdig*_test'(    fail, "\xFF").

test('hexdig*_success',[forall('hexdig*_test'(success,Input,Expected_result))]) :-
    DCG = 'hex_digit*'(Result),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]),

    assertion( Result == Expected_result ).

test('hexdig*_fail',[fail,forall('hexdig*_test'(fail,Input))]) :-
    DCG = 'hex_digit*'(_),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]).

proseval_test( success,                                                                   "<>" , prose("")        ).
proseval_test( success,                                                                  "< >" , prose(" ")       ).
proseval_test( success,                                                                 "<  >" , prose("  ")      ).
proseval_test( success,                                                               "<\x21>" , prose("!")       ).
proseval_test( success,                                                               "<\x3F>" , prose("?")       ).
proseval_test( success,                                                               "<\x7E>" , prose("~")       ).
proseval_test( success,                                    "< \u0021\u003F\u0040\u007D\u007E>" , prose(" !?@}~")  ).
proseval_test( success,                                                               "<aaaa>" , prose("aaaa")    ).
proseval_test( success, "< !?@ABCDEFGHIJKLMNOPQRSUVWXYZ[\\]^_`abcdefghijklmnopqrustuvxyz{|}~>" , prose(" !?@ABCDEFGHIJKLMNOPQRSUVWXYZ[\\]^_`abcdefghijklmnopqrustuvxyz{|}~") ).
proseval_test(    fail,                                                                    "a" ).
proseval_test(    fail,                                                                    " " ).
proseval_test(    fail,                                                                    "<" ).
proseval_test(    fail,                                                                    ">" ).
proseval_test(    fail,                                                                 "\x00" ).
proseval_test(    fail,                                                                 "\x1F" ).
proseval_test(    fail,                                                                 "\x3E" ).
proseval_test(    fail,                                                                 "\x7F" ).
proseval_test(    fail,                                                                 "\x80" ).
proseval_test(    fail,                                                                 "\xFF" ).

test(proseval_success,[forall(proseval_test(success,Input,Expected_result))]) :-
    DCG = proseval(Prose),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]),

    assertion( Prose == Expected_result ).

test(proseval_fail,[fail,forall(proseval_test(fail,Input))]) :-
    DCG = proseval(_),
    string_codes(Input,Codes),
    phrase(DCG,Codes,[]).

:- end_tests(abnf).