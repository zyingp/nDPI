%option noyywrap
%{
#include <stddef.h>  // for offsetof
#include "dsm.h"
#include "dsm.tab.h"
%}

/* float exponent */
EXP	([Ee][-+]?[0-9]+)

%x COMMENT

%%
 /* single character ops */
"+" |
"-" |
"*" |
"/" |
"=" |
"|" |
"," |
";" |
"[" |
"]" |
"{" |
"}" |
"'" |
"(" |
")"     { return yytext[0]; }

 /* comparison ops */
">"     { yylval.fn = 1; return CMP; }
"<"     { yylval.fn = 2; return CMP; }
"<>"    { yylval.fn = 3; return CMP; }
"=="    { yylval.fn = 4; return CMP; }
">="    { yylval.fn = 5; return CMP; }
"<="    { yylval.fn = 6; return CMP; }

"&&"    { yylval.fn = 7; return CON; }
"||"    { yylval.fn = 8; return CON; }

 /* keywords */

"if"    { return IF; }
"then"  { return THEN; }
"else"  { return ELSE; }
"while" { return WHILE; }
"do"    { return DO; }
"let"   { return LET;}

"enter:" { return ENTER;}
"match:" { return MATCH;}
"try_parser:" { return TRY_PARSER;}
"per_packet:" { return PER_PACKET;}

 /* built in functions */
"sqrt"  { yylval.fn = B_sqrt; return FUNC; }
"exp"   { yylval.fn = B_exp; return FUNC; }
"log"   { yylval.fn = B_log; return FUNC; }
"print" { yylval.fn = B_print; return FUNC; }

 /* debug hack */
"debug"[0-9]+ { debug = atoi(&yytext[5]); printf("debug set to %d\n", debug); }

"tcp"            { yylval.d = 6; return NUMBER; }
"udp"            { yylval.d = 17; return NUMBER; }

"protocol"              { yylval.s = lookup(yytext); yylval.s->type = symtype_base_uint8_indexed;
    yylval.s->index = offsetof(struct dsm_flow_data, protocol); return NAME; }
"server_port"           { yylval.s = lookup(yytext); yylval.s->type = symtype_base_uint16_indexed;
    yylval.s->index = offsetof(struct dsm_flow_data, server_port); return NAME; }
"pkt_num"           { yylval.s = lookup(yytext); yylval.s->type = symtype_base_uint8_indexed;
    yylval.s->index = offsetof(struct dsm_flow_data, pkt_num); return NAME; }
"payload_pkt_num"           { yylval.s = lookup(yytext); yylval.s->type = symtype_base_uint8_indexed;
    yylval.s->index = offsetof(struct dsm_flow_data, payload_pkt_num); return NAME; }
"payload_len"           { yylval.s = lookup(yytext); yylval.s->type = symtype_base_uint16_indexed;
    yylval.s->index = offsetof(struct dsm_flow_data, payload_len); return NAME; }
"payload"           { yylval.s = lookup(yytext); yylval.s->type = symtype_base_uint8pointer_indexed;
    yylval.s->index = offsetof(struct dsm_flow_data, payload); return NAME; }


 /* names */
[a-zA-Z_][a-zA-Z0-9_]*  { yylval.s = lookup(yytext); return NAME; }

 /* strings */

'(\\.|''|[^'\n])*' |
\"(\\.|\"\"|[^"\n])*\" { yylval.s = lookup(yytext); return STRING; }
'(\\.|[^'\n])*$ { yyerror("Unterminated string %s", yytext); }
\"(\\.|[^"\n])*$ { yyerror("Unterminated string %s", yytext); }

 /* hex strings */
X'[0-9A-F]+' |
0X[0-9A-F]+ { yylval.s = lookup(yytext); return STRING; }



[0-9]+"."[0-9]*{EXP}? |
"."?[0-9]+{EXP}? { yylval.d = atof(yytext); return NUMBER; }



"//".*  
"#".*   /* for # comments*/

"/*" { BEGIN COMMENT; /* switch to comment mode */ }
<COMMENT>. | 
<COMMENT>\n ; /* throw away comment text */
<COMMENT>"*/" { BEGIN INITIAL; /* return to regular mode */ }

[ \t]   /* ignore white space */ 
\\\n    printf("c> "); /* ignore line continuation */
"\n"    { return EOL; }

.	{ yyerror("Mystery character %c\n", *yytext); }
%%
